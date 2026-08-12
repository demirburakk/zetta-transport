use crate::crypto::CryptoEngine;
use crate::error::{Result, ZtError};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use super::state::{
    AckTracker, ConnectionState, PacketSpace, ReplayWindow, StreamState, UnackedPayload,
    UnackedWindow,
};

/// Represents a single connection to a remote peer.
///
/// Holds all per-connection state: addressing, crypto, streams,
/// packet tracking, and congestion/flow control parameters.
pub(crate) struct ZtConnection {
    pub(crate) addr: SocketAddr,
    pub(crate) dcid: Vec<u8>,
    pub(crate) scid: Vec<u8>,
    pub(crate) state: ConnectionState,
    pub(crate) next_packet_number: u64,
    pub(crate) crypto: Option<Box<dyn CryptoEngine>>,
    #[allow(dead_code)]
    pub(crate) initial_space: PacketSpace,
    #[allow(dead_code)]
    pub(crate) handshake_space: PacketSpace,
    #[allow(dead_code)]
    pub(crate) app_space: PacketSpace,

    pub(crate) streams: HashMap<u32, StreamState>,
    pub(crate) mtu_probes: HashMap<u64, usize>,

    pub(crate) unacked_packets: UnackedWindow,

    pub(crate) rtt: Duration,
    pub(crate) rttvar: Duration,
    pub(crate) rtt_initialized: bool,
    pub(crate) local_window: u64,
    pub(crate) remote_window: u64,

    pub(crate) cc: Box<dyn crate::transport::congestion::CongestionController>,
    pub(crate) pacing_tokens: f64,
    pub(crate) last_pacing_update: Option<std::time::Instant>,
    pub(crate) bytes_in_flight: usize,
    pub(crate) mtu: usize,
    pub(crate) shared_mtu: Arc<std::sync::atomic::AtomicUsize>,
    pub(crate) mtu_min: usize,
    pub(crate) mtu_max: usize,
    pub(crate) base_mtu: usize,
    pub(crate) bytes_received: usize,
    pub(crate) bytes_sent: usize,
    pub(crate) conn_tx_offset: u64,

    pub(crate) unpaced_queue: std::collections::VecDeque<(UnackedPayload, u32)>,
    pub(crate) queued_bytes: usize,

    pub(crate) replay_window: ReplayWindow,
    pub(crate) ack_tracker: AckTracker,

    pub(crate) current_key_epoch: u64,
    pub(crate) packets_since_key_update: u64,
    pub(crate) cookie: Option<bytes::Bytes>,
    pub(crate) handshake_packet: Option<bytes::Bytes>,
    /// Shared closed flag for all streams. Set to true when the connection
    /// is closing/closed to unblock pending ZtStream::send() calls.
    pub(crate) closed: Arc<AtomicBool>,
    pub(crate) largest_acked_received_at: Option<std::time::Instant>,
    pub(crate) local_max_streams: u64,
    pub(crate) peer_max_streams: u64,
    pub(crate) peer_initial_stream_window: u64,
    pub(crate) peer_max_datagram_size: usize,
    pub(crate) idle_timeout: Duration,
    pub(crate) termination: Arc<crate::stream::termination::Termination>,
    pub(crate) packets_lost: u64,
    pub(crate) packets_retransmitted: u64,
    pub(crate) mtu_probe_successes: u64,
    pub(crate) mtu_probe_failures: u64,
    pub(crate) mtu_blackhole_recoveries: u64,
}

impl ZtConnection {
    #[allow(dead_code)]
    pub(crate) fn new(addr: SocketAddr, scid: Vec<u8>, dcid: Vec<u8>) -> Self {
        Self::new_with_cc(
            addr,
            scid,
            dcid,
            crate::transport::congestion::CongestionControlAlgorithm::Cubic,
        )
    }

    pub(crate) fn new_with_cc(
        addr: SocketAddr,
        scid: Vec<u8>,
        dcid: Vec<u8>,
        cc_algo: crate::transport::congestion::CongestionControlAlgorithm,
    ) -> Self {
        let config = crate::config::ZtConfig {
            cc_algorithm: cc_algo,
            ..crate::config::ZtConfig::default()
        };
        Self::new_with_config(addr, scid, dcid, &config)
    }

    pub(crate) fn new_with_config(
        addr: SocketAddr,
        scid: Vec<u8>,
        dcid: Vec<u8>,
        config: &crate::config::ZtConfig,
    ) -> Self {
        let mtu = config.mtu_min;
        let initial_cwnd = 10 * mtu;
        let cc: Box<dyn crate::transport::congestion::CongestionController> =
            match config.cc_algorithm {
                crate::transport::congestion::CongestionControlAlgorithm::Cubic => Box::new(
                    crate::transport::congestion::CubicController::new(initial_cwnd, mtu),
                ),
                crate::transport::congestion::CongestionControlAlgorithm::Reno => Box::new(
                    crate::transport::congestion::RenoController::new(initial_cwnd, mtu),
                ),
            };

        Self {
            addr,
            dcid,
            scid,
            state: ConnectionState::Handshaking,
            next_packet_number: 0,
            crypto: None,
            initial_space: PacketSpace::new(),
            handshake_space: PacketSpace::new(),
            app_space: PacketSpace::new(),

            streams: HashMap::new(),
            mtu_probes: HashMap::new(),
            unacked_packets: UnackedWindow::new(),

            rtt: Duration::from_millis(333),
            rttvar: Duration::from_millis(166),
            rtt_initialized: false,

            local_window: config.initial_max_data,
            remote_window: config.initial_max_data,

            cc,
            pacing_tokens: initial_cwnd as f64,
            last_pacing_update: None,
            bytes_in_flight: 0,
            mtu,
            shared_mtu: Arc::new(std::sync::atomic::AtomicUsize::new(mtu)),
            mtu_min: config.mtu_min,
            mtu_max: config.mtu_max,
            base_mtu: config.mtu_min,
            bytes_received: 0,
            bytes_sent: 0,
            conn_tx_offset: 0,

            unpaced_queue: std::collections::VecDeque::new(),
            queued_bytes: 0,

            replay_window: ReplayWindow::new(),
            ack_tracker: AckTracker::new(),

            current_key_epoch: 0,
            packets_since_key_update: 0,
            cookie: None,
            handshake_packet: None,
            closed: Arc::new(AtomicBool::new(false)),
            largest_acked_received_at: None,
            local_max_streams: config.max_concurrent_streams,
            peer_max_streams: config.max_concurrent_streams,
            peer_initial_stream_window: config.initial_stream_window,
            peer_max_datagram_size: config.mtu_min.saturating_sub(64),
            idle_timeout: config.idle_timeout,
            termination: Arc::new(crate::stream::termination::Termination::default()),
            packets_lost: 0,
            packets_retransmitted: 0,
            mtu_probe_successes: 0,
            mtu_probe_failures: 0,
            mtu_blackhole_recoveries: 0,
        }
    }

    pub(crate) fn get_next_packet_number(&mut self) -> Result<u64> {
        let n = self.next_packet_number;
        self.next_packet_number = self
            .next_packet_number
            .checked_add(1)
            .ok_or(ZtError::PacketNumberOverflow)?;
        Ok(n)
    }

    pub(crate) fn get_total_buffered_bytes(&self) -> usize {
        self.streams.values().map(|s| s.buffered_bytes).sum()
    }

    pub(crate) fn total_allocated_buffer_size(&self) -> usize {
        self.streams
            .values()
            .map(|stream| stream.receive_buffer.allocated_size())
            .fold(0usize, usize::saturating_add)
    }

    pub(crate) fn record_mtu_probe_success(&mut self, target_size: usize) {
        self.mtu_probe_successes = self.mtu_probe_successes.saturating_add(1);
        self.mtu_min = self.mtu_min.max(target_size);
        if target_size > self.mtu {
            self.mtu = target_size;
            self.shared_mtu
                .store(target_size, std::sync::atomic::Ordering::Relaxed);
            self.cc.set_mtu(target_size);
        }
    }

    pub(crate) fn record_mtu_probe_failure(&mut self, target_size: usize) {
        self.mtu_probe_failures = self.mtu_probe_failures.saturating_add(1);
        self.mtu_max = self.mtu_max.min(target_size.saturating_sub(1));
    }

    pub(crate) fn recover_mtu_blackhole(&mut self) -> bool {
        if self.mtu <= self.base_mtu {
            return false;
        }
        let previous_mtu = self.mtu;
        self.mtu = self.base_mtu;
        self.mtu_min = self.base_mtu;
        self.mtu_max = previous_mtu.saturating_sub(1).max(self.base_mtu);
        self.shared_mtu
            .store(self.base_mtu, std::sync::atomic::Ordering::Relaxed);
        self.cc.set_mtu(self.base_mtu);
        self.mtu_blackhole_recoveries = self.mtu_blackhole_recoveries.saturating_add(1);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::ZtConnection;
    use crate::config::ZtConfig;

    fn connection() -> ZtConnection {
        ZtConnection::new_with_config(
            "127.0.0.1:4433".parse().unwrap(),
            vec![1; 8],
            vec![2; 8],
            &ZtConfig::default(),
        )
    }

    #[test]
    fn pmtud_binary_search_bounds_follow_probe_results() {
        let mut connection = connection();
        connection.record_mtu_probe_failure(5100);
        assert_eq!(connection.mtu_max, 5099);
        connection.record_mtu_probe_success(3149);
        assert_eq!(connection.mtu, 3149);
        assert_eq!(connection.mtu_min, 3149);
        assert_eq!(connection.mtu_probe_failures, 1);
        assert_eq!(connection.mtu_probe_successes, 1);
    }

    #[test]
    fn pmtud_blackhole_rolls_back_and_restarts_search_below_failed_mtu() {
        let mut connection = connection();
        connection.record_mtu_probe_success(4096);
        assert!(connection.recover_mtu_blackhole());
        assert_eq!(connection.mtu, 1200);
        assert_eq!(connection.mtu_min, 1200);
        assert_eq!(connection.mtu_max, 4095);
        assert_eq!(connection.mtu_blackhole_recoveries, 1);
        assert!(!connection.recover_mtu_blackhole());
    }
}
