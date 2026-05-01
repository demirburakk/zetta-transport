use super::connection::ZtConnection;
use crate::transport::stream_state::UnackedPayload;

/// Congestion control, loss recovery, and replay protection for a connection.
impl ZtConnection {
    /// Checks if a packet number has already been processed (replay detection).
    pub(crate) fn is_replay(&self, pn: u64) -> bool {
        self.replay_window.is_replay(pn)
    }

    /// Marks a packet number as processed in the replay bitmask.
    pub(crate) fn mark_processed(&mut self, pn: u64) {
        self.replay_window.mark_processed(pn)
    }

    /// Builds ACK ranges from the replay bitmask for selective acknowledgment.
    pub(crate) fn get_ack_ranges(&self) -> Vec<(u64, u64)> {
        self.replay_window.get_ack_ranges()
    }

    /// Processes an ACK frame: removes acked packets, updates RTT, adjusts
    /// congestion window, and notifies blocked streams.
    pub(crate) fn handle_ack(
        &mut self,
        largest_acked_pn: u64,
        window_size: u32,
        sack_ranges: &[(u64, u64)],
        fast_retransmits: &mut Vec<UnackedPayload>,
    ) {
        let mut bytes_acked = 0usize;
        let mut sample_rtt = None;

        // 1. Process SACK ranges first (Selective ACK)
        for &(start, end) in sack_ranges {
            let mut range = Vec::new();
            for (pn, _) in self.unacked_packets.iter() {
                if pn >= start && pn <= end {
                    range.push(pn);
                }
            }
            for pn in range {
                if let Some(up) = self.unacked_packets.remove(pn) {
                    bytes_acked += up.payload.len();
                    if sample_rtt.is_none() {
                        sample_rtt = Some(up.sent_at.elapsed());
                    }
                    if up.is_mtu_probe
                        && self.mtu_probes.remove(&pn).is_some()
                        && up.payload.len() > self.mtu
                    {
                        self.mtu = up.payload.len();
                        tracing::info!("MTU upgraded to {} via SACK'd PMTUD", self.mtu);
                    }
                }
            }
        }

        // 2. Process cumulative ACK (everything <= largest_acked_pn)
        let acked_pns: Vec<u64> = self
            .unacked_packets
            .keys()
            .take_while(|&pn| pn <= largest_acked_pn)
            .collect();

        for pn in acked_pns {
            if let Some(up) = self.unacked_packets.remove(pn) {
                bytes_acked += up.payload.len();
                if sample_rtt.is_none() {
                    sample_rtt = Some(up.sent_at.elapsed());
                }
                if up.is_mtu_probe
                    && self.mtu_probes.remove(&pn).is_some()
                    && up.payload.len() > self.mtu
                {
                    self.mtu = up.payload.len();
                    tracing::info!("MTU upgraded to {} via PMTUD", self.mtu);
                }
            }
        }
        
        // 3. Fast Retransmit Detection (SACK-based gap detection)
        // Any unacked packet that is strictly less than largest_acked_pn - 3
        // is considered lost and must be retransmitted immediately.
        let mut lost_pns = Vec::new();
        for (pn, _up) in self.unacked_packets.iter() {
            if pn + 3 <= largest_acked_pn {
                lost_pns.push(pn);
            }
        }
        for pn in lost_pns {
            if let Some(up) = self.unacked_packets.remove(pn) {
                fast_retransmits.push(up.payload);
                self.handle_loss();
            }
        }

        self.bytes_in_flight = self.bytes_in_flight.saturating_sub(bytes_acked);

        if let Some(rtt) = sample_rtt {
            if !self.rtt_initialized {
                self.rtt = rtt;
                self.rttvar = rtt / 2;
                self.rtt_initialized = true;
            } else {
                let error = self.rtt.abs_diff(rtt);
                self.rttvar = (self.rttvar * 3 + error) / 4;
                self.rtt = (self.rtt * 7 + rtt) / 8;
            }
        }

        if bytes_acked > 0 {
            if self.cwnd < self.ssthresh {
                self.cwnd += bytes_acked;
            } else {
                self.cwnd += (self.mtu * bytes_acked) / self.cwnd.max(self.mtu);
            }
        }

        self.remote_window = window_size;

        for stream in self.streams.values() {
            stream.window_opened.notify_waiters();
        }
    }

    /// Adjusts congestion window after packet loss detection.
    pub(crate) fn handle_loss(&mut self) {
        self.ssthresh = (self.cwnd / 2).max(self.mtu * 2);
        self.cwnd = self.ssthresh + 3 * self.mtu;
    }
}
