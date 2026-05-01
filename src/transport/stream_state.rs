use bytes::Bytes;
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::{Notify, mpsc};

/// Lifecycle states of a connection.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) enum ConnectionState {
    Handshaking,
    Active,
    Closing,
    Closed,
}

/// Per-stream receive/transmit state.
pub(crate) struct StreamState {
    pub(crate) expected_rx_offset: u64,
    pub(crate) next_tx_offset: u64,
    pub(crate) chunks: BTreeMap<u64, Bytes>, // Scatter-gather chunks instead of ring buffer
    pub(crate) window_size: u64,
    pub(crate) buffered_bytes: usize,
    pub(crate) window_opened: Arc<Notify>,
    pub(crate) app_tx: mpsc::Sender<Bytes>,
}

impl StreamState {
    pub(crate) fn new(app_tx: mpsc::Sender<Bytes>, window_opened: Arc<Notify>) -> Self {
        Self {
            expected_rx_offset: 0,
            next_tx_offset: 0,
            chunks: BTreeMap::new(),
            window_size: 1024 * 1024,
            buffered_bytes: 0,
            window_opened,
            app_tx,
        }
    }
}

/// Describes the content of an unacknowledged packet.
pub(crate) enum UnackedPayload {
    Stream {
        stream_id: u32,
        offset: u64,
        data: Bytes,
    },
    MtuProbe {
        target_size: usize,
    },
    StreamClose {
        stream_id: u32,
    },
    Close,
}

impl UnackedPayload {
    pub(crate) fn len(&self) -> usize {
        match self {
            UnackedPayload::Stream { data, .. } => data.len(),
            UnackedPayload::MtuProbe { target_size } => *target_size,
            UnackedPayload::StreamClose { .. } | UnackedPayload::Close => 0,
        }
    }
}

/// A packet that has been sent but not yet acknowledged.
pub(crate) struct UnackedPacket {
    pub(crate) payload: UnackedPayload,
    pub(crate) sent_at: Instant,
    pub(crate) retries: u32,
    pub(crate) is_mtu_probe: bool,
}
