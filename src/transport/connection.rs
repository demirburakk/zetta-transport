use crate::crypto::CryptoContext;
use crate::error::{Result, ZtError};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;

use super::state::{
    AckTracker, ConnectionState, ReplayWindow, StreamState, UnackedPayload, UnackedWindow,
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
    pub(crate) crypto: Option<CryptoContext>,

    pub(crate) streams: HashMap<u32, StreamState>,
    pub(crate) mtu_probes: HashMap<u64, usize>,

    pub(crate) unacked_packets: UnackedWindow,

    pub(crate) rtt: Duration,
    pub(crate) rttvar: Duration,
    pub(crate) rtt_initialized: bool,
    pub(crate) local_window: u32,
    pub(crate) remote_window: u32,

    pub(crate) cc: Box<dyn crate::transport::congestion::CongestionController>,
    pub(crate) pacing_tokens: f64,
    pub(crate) last_pacing_update: Option<std::time::Instant>,
    pub(crate) bytes_in_flight: usize,
    pub(crate) mtu: usize,
    pub(crate) shared_mtu: Arc<std::sync::atomic::AtomicUsize>,
    pub(crate) mtu_min: usize,
    pub(crate) mtu_max: usize,
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
}

impl ZtConnection {
    // Maximum concurrent streams allowed. With 1MB window_size, this limits total
    // stream buffer memory to ~100MB max per connection.
    pub(crate) const MAX_CONCURRENT_STREAMS: usize = 100;

    #[allow(dead_code)]
    pub(crate) fn new(addr: SocketAddr, scid: Vec<u8>, dcid: Vec<u8>) -> Self {
        Self::new_with_cc(addr, scid, dcid, crate::transport::congestion::CongestionControlAlgorithm::Cubic)
    }

    pub(crate) fn new_with_cc(
        addr: SocketAddr,
        scid: Vec<u8>,
        dcid: Vec<u8>,
        cc_algo: crate::transport::congestion::CongestionControlAlgorithm,
    ) -> Self {
        let initial_cwnd = 10 * 1200;
        let mtu = 1200;
        let cc: Box<dyn crate::transport::congestion::CongestionController> = match cc_algo {
            crate::transport::congestion::CongestionControlAlgorithm::Cubic => {
                Box::new(crate::transport::congestion::CubicController::new(initial_cwnd, mtu))
            }
            crate::transport::congestion::CongestionControlAlgorithm::Reno => {
                Box::new(crate::transport::congestion::RenoController::new(initial_cwnd, mtu))
            }
        };

        Self {
            addr,
            dcid,
            scid,
            state: ConnectionState::Handshaking,
            next_packet_number: 0,
            crypto: None,

            streams: HashMap::new(),
            mtu_probes: HashMap::new(),
            unacked_packets: UnackedWindow::new(),

            rtt: Duration::from_millis(333),
            rttvar: Duration::from_millis(166),
            rtt_initialized: false,

            local_window: 1024 * 1024,
            remote_window: 1024 * 1024,

            cc,
            pacing_tokens: 12000.0, // Initial burst
            last_pacing_update: None,
            bytes_in_flight: 0,
            mtu,
            shared_mtu: Arc::new(std::sync::atomic::AtomicUsize::new(mtu)),
            mtu_min: 1200,
            mtu_max: 9000,
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
        self.streams
            .values()
            .map(|s| s.buffered_bytes)
            .sum()
    }
}
