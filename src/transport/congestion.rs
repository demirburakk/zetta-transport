use super::connection::ZtConnection;
use crate::transport::state::UnackedPayload;
use std::time::Duration;

/// Supported congestion control algorithms for ZettaTransport.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CongestionControlAlgorithm {
    /// CUBIC congestion control (RFC 8312). Scales the congestion window as a cubic
    /// function of the time elapsed since the last congestion event, making it window-growth
    /// independent of RTT. Useful for high-bandwidth delay-product (BDP) networks.
    Cubic,
    /// TCP Reno congestion control. Classic Additive Increase Multiplicative Decrease (AIMD)
    /// algorithm. Increases window by 1 segment per RTT in congestion avoidance, and halves
    /// the window upon packet loss detection.
    Reno,
}

/// Pluggable interface for transport congestion controllers.
/// Manages the size of the congestion window (cwnd) and slow-start threshold (ssthresh)
/// based on packet events such as transmissions, ACKs, and loss-induced congestion.
#[allow(dead_code)]
pub(crate) trait CongestionController: Send + Sync {
    /// Invoked when a packet is sent out. Allows tracking of outstanding bytes and pacing.
    fn on_packet_sent(&mut self, pn: u64, bytes: usize, sent_at: std::time::Instant);
    
    /// Invoked when one or more packets are acknowledged. Updates the congestion window
    /// according to the active phase (slow start vs congestion avoidance).
    fn on_packet_acked(
        &mut self,
        bytes_acked: usize,
        rtt: std::time::Duration,
        now: std::time::Instant,
    );
    
    /// Invoked when a loss event is detected (e.g. triple duplicate ACKs or RTO timeout).
    /// Halves the window (or performs Cubic convergence reduction) and updates ssthresh.
    fn on_congestion_event(
        &mut self,
        rtt: std::time::Duration,
        now: std::time::Instant,
    );
    
    /// Returns the current congestion window size in bytes.
    fn cwnd(&self) -> usize;
    
    /// Returns the current slow start threshold in bytes.
    fn ssthresh(&self) -> usize;
    
    /// Mutates the congestion window size.
    fn set_cwnd(&mut self, cwnd: usize);
    
    /// Mutates the slow start threshold size.
    fn set_ssthresh(&mut self, ssthresh: usize);
    
    /// Updates the Maximum Transmission Unit (MTU) used to calculate segment boundaries.
    fn set_mtu(&mut self, mtu: usize);
}

/// An implementation of CUBIC congestion control (RFC 8312).
/// CUBIC modifies the linear window growth of Reno to a cubic function of the elapsed
/// time since the last packet loss.
pub(crate) struct CubicController {
    /// Current congestion window size in bytes.
    cwnd: usize,
    /// Slow start threshold in bytes.
    ssthresh: usize,
    /// Maximum Transmission Unit (MTU) or segment size in bytes.
    mtu: usize,
    /// The maximum window size before the last reduction, in packets.
    cubic_w_max: f64,
    /// The time period in seconds required to scale the window back to `cubic_w_max`.
    cubic_k: f64,
    /// Timestamp of the last congestion event (loss detection).
    last_congestion_time: Option<std::time::Instant>,
    /// Timestamp of the last time the CUBIC target window was updated.
    last_cubic_update: Option<std::time::Instant>,
    /// Timestamp indicating the start of the current CUBIC epoch.
    cubic_epoch_start: Option<std::time::Instant>,
    /// The target congestion window calculated via the cubic growth function.
    target_cwnd: usize,
}

impl CubicController {
    /// Instantiates a new CUBIC congestion controller with the specified initial window and MTU.
    pub fn new(initial_cwnd: usize, mtu: usize) -> Self {
        Self {
            cwnd: initial_cwnd,
            ssthresh: usize::MAX,
            mtu,
            cubic_w_max: 0.0,
            cubic_k: 0.0,
            last_congestion_time: None,
            last_cubic_update: None,
            cubic_epoch_start: None,
            target_cwnd: initial_cwnd,
        }
    }
}

impl CongestionController for CubicController {
    fn on_packet_sent(&mut self, _pn: u64, _bytes: usize, _sent_at: std::time::Instant) {}

    fn on_packet_acked(
        &mut self,
        bytes_acked: usize,
        rtt: std::time::Duration,
        now: std::time::Instant,
    ) {
        if self.cwnd < self.ssthresh {
            // Slow start
            self.cwnd += bytes_acked;
        } else {
            // Start a new CUBIC epoch if we just entered congestion avoidance.
            if self.cubic_epoch_start.is_none() {
                self.cubic_epoch_start = Some(now);
            }

            let should_update = match self.last_cubic_update {
                Some(last) => now.duration_since(last) >= rtt,
                None => true,
            };
            
            if should_update {
                self.last_cubic_update = Some(now);
                let c = 0.4;
                let t = self
                    .cubic_epoch_start
                    .map_or(0.0, |epoch| now.duration_since(epoch).as_secs_f64());

                let w_cubic_pkts = c * (t - self.cubic_k).powi(3) + self.cubic_w_max;
                self.target_cwnd = (w_cubic_pkts * self.mtu as f64).max(0.0) as usize;
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

    fn on_congestion_event(
        &mut self,
        rtt: std::time::Duration,
        now: std::time::Instant,
    ) {
        if let Some(last_loss) = self.last_congestion_time
            && now.duration_since(last_loss) < rtt {
                return; // Reduce cwnd at most once per RTT
            }
        self.last_congestion_time = Some(now);

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

        self.cubic_k = ((self.cubic_w_max * (1.0 - beta)) / c).powf(1.0 / 3.0);
        self.cubic_epoch_start = None;
        self.last_cubic_update = None;
    }

    fn cwnd(&self) -> usize { self.cwnd }
    fn ssthresh(&self) -> usize { self.ssthresh }
    fn set_cwnd(&mut self, cwnd: usize) { self.cwnd = cwnd; }
    fn set_ssthresh(&mut self, ssthresh: usize) { self.ssthresh = ssthresh; }
    fn set_mtu(&mut self, mtu: usize) { self.mtu = mtu; }
}

/// An implementation of classic TCP Reno congestion control (AIMD).
/// Increases congestion window by 1 packet per RTT during congestion avoidance,
/// and cuts the window in half upon a congestion event.
pub(crate) struct RenoController {
    /// Current congestion window size in bytes.
    cwnd: usize,
    /// Slow start threshold in bytes.
    ssthresh: usize,
    /// Maximum Transmission Unit (MTU) or segment size in bytes.
    mtu: usize,
    /// Timestamp of the last congestion event (used to prevent multiple reductions in the same RTT).
    last_congestion_time: Option<std::time::Instant>,
}

impl RenoController {
    /// Instantiates a new Reno congestion controller with the specified initial window and MTU.
    pub fn new(initial_cwnd: usize, mtu: usize) -> Self {
        Self {
            cwnd: initial_cwnd,
            ssthresh: usize::MAX,
            mtu,
            last_congestion_time: None,
        }
    }
}

impl CongestionController for RenoController {
    fn on_packet_sent(&mut self, _pn: u64, _bytes: usize, _sent_at: std::time::Instant) {}

    fn on_packet_acked(
        &mut self,
        bytes_acked: usize,
        _rtt: std::time::Duration,
        _now: std::time::Instant,
    ) {
        if self.cwnd < self.ssthresh {
            // Slow start
            self.cwnd += bytes_acked;
        } else {
            // Congestion avoidance (AIMD)
            let increment = (self.mtu * bytes_acked) / self.cwnd.max(self.mtu);
            self.cwnd += increment.max(1);
        }
    }

    fn on_congestion_event(
        &mut self,
        rtt: std::time::Duration,
        now: std::time::Instant,
    ) {
        if let Some(last_loss) = self.last_congestion_time
            && now.duration_since(last_loss) < rtt {
                return; // Reduce cwnd at most once per RTT
            }
        self.last_congestion_time = Some(now);

        self.ssthresh = (self.cwnd / 2).max(self.mtu * 2);
        self.cwnd = self.ssthresh;
    }

    fn cwnd(&self) -> usize { self.cwnd }
    fn ssthresh(&self) -> usize { self.ssthresh }
    fn set_cwnd(&mut self, cwnd: usize) { self.cwnd = cwnd; }
    fn set_ssthresh(&mut self, ssthresh: usize) { self.ssthresh = ssthresh; }
    fn set_mtu(&mut self, mtu: usize) { self.mtu = mtu; }
}

impl ZtConnection {
    /// Checks if a packet number has already been processed (replay detection).
    pub(crate) fn is_replay(&self, pn: u64) -> bool {
        self.replay_window.is_replay(pn)
    }

    /// Marks a packet number as processed in the replay bitmask and ACK tracker.
    pub(crate) fn mark_processed(&mut self, pn: u64) {
        let is_new_highest = self.ack_tracker.highest_processed.is_none_or(|h| pn >= h);
        if is_new_highest {
            self.largest_acked_received_at = Some(std::time::Instant::now());
        }
        self.replay_window.mark_processed(pn);
        self.ack_tracker.mark_processed(pn);
    }

    /// Builds ACK ranges from the ACK tracker for selective acknowledgment.
    pub(crate) fn get_ack_ranges(&self) -> Vec<(u64, u64)> {
        self.ack_tracker.get_ack_ranges()
    }

    /// Processes an ACK frame: removes acked packets, updates RTT, adjusts
    /// congestion window, and notifies blocked streams.
    pub(crate) fn handle_ack(
        &mut self,
        largest_acked_pn: u64,
        window_size: u32,
        ack_delay_us: u64,
        sack_ranges: &[(u64, u64)],
        fast_retransmits: &mut Vec<(UnackedPayload, u32)>,
    ) {
        let mut bytes_acked = 0usize;
        let mut bytes_in_flight_acked = 0usize;
        let mut sample_rtt = None;

        // 1. Process SACK ranges first (Selective ACK)
        for &(start, end) in sack_ranges {
            let lower = start.max(self.unacked_packets.base_pn);
            let upper = end.min(self.unacked_packets.base_pn + self.unacked_packets.deque.len() as u64);
            if lower <= upper {
                for pn in lower..=upper {
                    if let Some(up) = self.unacked_packets.remove(pn) {
                        if !up.is_mtu_probe {
                            bytes_acked += up.payload.len();
                        }
                        bytes_in_flight_acked += up.sent_bytes;
                        if sample_rtt.is_none() && up.retries == 0 {
                            sample_rtt = Some(up.sent_at.elapsed());
                        }
                        if up.is_mtu_probe
                            && self.mtu_probes.remove(&pn).is_some()
                            && up.payload.len() > self.mtu
                        {
                            let new_mtu = up.payload.len();
                            self.mtu = new_mtu;
                            self.shared_mtu.store(new_mtu, std::sync::atomic::Ordering::Relaxed);
                            self.cc.set_mtu(new_mtu);
                            tracing::info!("MTU upgraded to {} via SACK'd PMTUD", self.mtu);
                        }
                    }
                }
            }
        }

        // 2. Cumulative ACK: Acknowledge packets that are older than the 2048-packet window tracking limit.
        let oldest_tracked = largest_acked_pn.saturating_sub(2047);
        let mut cumulative_acked = Vec::new();
        for (pn, _) in self.unacked_packets.iter() {
            if pn < oldest_tracked {
                cumulative_acked.push(pn);
            } else {
                break;
            }
        }
        for pn in cumulative_acked {
            if let Some(up) = self.unacked_packets.remove(pn) {
                if !up.is_mtu_probe {
                    bytes_acked += up.payload.len();
                }
                bytes_in_flight_acked += up.sent_bytes;
                if sample_rtt.is_none() && up.retries == 0 {
                    sample_rtt = Some(up.sent_at.elapsed());
                }
            }
        }

        // 3. Fast Retransmit Detection (SACK-based gap and time-based threshold detection)
        let mut lost_pns = Vec::new();
        let now = std::time::Instant::now();
        let time_threshold = self.rtt.mul_f64(1.25).max(std::time::Duration::from_millis(15));
        for (pn, up) in self.unacked_packets.iter() {
            if pn < largest_acked_pn {
                let packet_threshold = pn + 3 <= largest_acked_pn;
                let time_threshold_met = now.duration_since(up.sent_at) > time_threshold;
                if packet_threshold || time_threshold_met {
                    lost_pns.push(pn);
                }
            } else {
                break;
            }
        }
        let mut loss_detected = false;
        for pn in lost_pns {
            if let Some(up) = self.unacked_packets.remove(pn) {
                self.bytes_in_flight = self.bytes_in_flight.saturating_sub(up.sent_bytes);
                if up.is_mtu_probe {
                    self.mtu_probes.remove(&pn);
                } else if matches!(up.payload, UnackedPayload::Datagram { .. }) {
                    // Do not retransmit datagram!
                    loss_detected = true;
                } else {
                    fast_retransmits.push((up.payload, up.retries));
                    loss_detected = true;
                }
            }
        }
        if loss_detected {
            self.cc.on_congestion_event(self.rtt, now);
        }

        self.bytes_in_flight = self
            .bytes_in_flight
            .saturating_sub(bytes_in_flight_acked);

        if let Some(mut rtt) = sample_rtt {
            let ack_delay = Duration::from_micros(ack_delay_us);
            if rtt > ack_delay {
                rtt -= ack_delay;
            }
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
            self.cc.on_packet_acked(bytes_acked, self.rtt, now);
        }

        let old_remote_window = self.remote_window;
        self.remote_window = window_size;

        if window_size > old_remote_window || bytes_acked > 0 {
            for stream in self.streams.values() {
                stream.window_opened.notify_waiters();
            }
        }
    }
}
