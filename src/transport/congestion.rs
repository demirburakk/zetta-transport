use super::connection::ZtConnection;
use crate::transport::state::UnackedPayload;

/// Congestion control, loss recovery, and replay protection for a connection.
impl ZtConnection {
    /// Checks if a packet number has already been processed (replay detection).
    pub(crate) fn is_replay(&self, pn: u64) -> bool {
        self.replay_window.is_replay(pn)
    }

    /// Marks a packet number as processed in the replay bitmask and ACK tracker.
    pub(crate) fn mark_processed(&mut self, pn: u64) {
        self.replay_window.mark_processed(pn);
        self.ack_tracker.mark_processed(pn);
    }

    /// Builds ACK ranges from the ACK tracker for selective acknowledgment.
    pub(crate) fn get_ack_ranges(&self) -> Vec<(u64, u64)> {
        self.ack_tracker.get_ack_ranges()
    }

    /// Processes an ACK frame: removes acked packets, updates RTT, adjusts
    /// congestion window, and notifies blocked streams.
    ///
    /// Only notifies streams whose windows actually changed, avoiding
    /// unnecessary wakeups (thundering herd).
    pub(crate) fn handle_ack(
        &mut self,
        largest_acked_pn: u64,
        window_size: u32,
        sack_ranges: &[(u64, u64)],
        fast_retransmits: &mut Vec<UnackedPayload>,
    ) {
        let mut bytes_acked = 0usize;
        let mut bytes_in_flight_acked = 0usize;
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
                    bytes_in_flight_acked += up.sent_bytes;
                    if sample_rtt.is_none() && up.retries == 0 {
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
                bytes_in_flight_acked += up.sent_bytes;
                if sample_rtt.is_none() && up.retries == 0 {
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
        let mut loss_detected = false;
        for pn in lost_pns {
            if let Some(up) = self.unacked_packets.remove(pn) {
                self.bytes_in_flight = self.bytes_in_flight.saturating_sub(up.sent_bytes);
                if up.is_mtu_probe {
                    self.mtu_probes.remove(&pn);
                } else {
                    fast_retransmits.push(up.payload);
                    loss_detected = true;
                }
            }
        }
        if loss_detected {
            self.handle_loss();
        }

        self.bytes_in_flight = self
            .bytes_in_flight
            .saturating_sub(bytes_in_flight_acked);

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
                // Slow start
                self.cwnd += bytes_acked;
            } else {
                let should_update = match self.last_cubic_update {
                    Some(last) => last.elapsed() >= self.rtt,
                    None => true,
                };
                
                if should_update {
                    self.last_cubic_update = Some(std::time::Instant::now());
                    let c = 0.4;
                    let t = self
                        .last_congestion_time
                        .map_or(0.0, |last| last.elapsed().as_secs_f64());

                    let w_cubic_pkts = c * (t - self.cubic_k).powi(3) + self.cubic_w_max;
                    self.target_cwnd = (w_cubic_pkts * self.mtu as f64) as usize;
                }

                let target_cwnd = self.target_cwnd;
                let reno_inc = (self.mtu * bytes_acked) / self.cwnd.max(self.mtu);

                if target_cwnd > self.cwnd {
                    let cubic_inc = target_cwnd - self.cwnd;
                    self.cwnd += cubic_inc.min(bytes_acked); // Bound the increase by acked amount
                } else {
                    // Reno fallback (additive increase)
                    self.cwnd += reno_inc;
                }
            }
        }

        let old_remote_window = self.remote_window;
        self.remote_window = window_size;

        // Only notify streams when the global remote window actually grew,
        // avoiding unnecessary wakeups (Fix #7).
        if window_size > old_remote_window {
            for stream in self.streams.values() {
                stream.window_opened.notify_waiters();
            }
        }
    }

    /// Adjusts congestion window after packet loss detection.
    pub(crate) fn handle_loss(&mut self) {
        let beta = 0.7;
        let c = 0.4;
        
        let current_cwnd_pkts = self.cwnd as f64 / self.mtu as f64;
        
        // Fast convergence
        if current_cwnd_pkts < self.cubic_w_max {
            self.cubic_w_max = current_cwnd_pkts * (1.0 + beta) / 2.0;
        } else {
            self.cubic_w_max = current_cwnd_pkts;
        }

        self.ssthresh = ((self.cwnd as f64 * beta) as usize).max(self.mtu * 2);
        self.cwnd = self.ssthresh;
        
        self.cubic_k = (self.cubic_w_max * (1.0 - beta) / c).cbrt();
        self.last_congestion_time = Some(std::time::Instant::now());
    }
}
