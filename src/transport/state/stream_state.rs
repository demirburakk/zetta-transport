use crate::transport::state::StreamReceiveBuffer;
use bytes::Bytes;
use std::sync::Arc;
use tokio::sync::{Notify, mpsc};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Local capabilities of a multiplexed stream.
pub enum StreamType {
    /// Both local reads and local writes are permitted.
    Bidirectional,
    /// The local endpoint may write; the peer receives it as [`StreamType::UnidirectionalIn`].
    UnidirectionalOut,
    /// The local endpoint may only read. These streams are opened by the peer, not locally.
    UnidirectionalIn,
}

impl StreamType {
    pub(crate) fn to_wire(self) -> u8 {
        match self {
            Self::Bidirectional => 0,
            Self::UnidirectionalOut => 1,
            Self::UnidirectionalIn => 2,
        }
    }

    pub(crate) fn from_wire(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Bidirectional),
            1 => Some(Self::UnidirectionalOut),
            2 => Some(Self::UnidirectionalIn),
            _ => None,
        }
    }

    pub(crate) fn for_peer(self) -> Option<Self> {
        match self {
            Self::Bidirectional => Some(Self::Bidirectional),
            Self::UnidirectionalOut => Some(Self::UnidirectionalIn),
            Self::UnidirectionalIn => None,
        }
    }
}

/// Per-stream receive/transmit state.
pub(crate) struct StreamState {
    pub(crate) expected_rx_offset: u64,
    pub(crate) next_tx_offset: u64,
    pub(crate) receive_buffer: StreamReceiveBuffer,
    pub(crate) window_size: u64,
    pub(crate) tx_window: u64,
    pub(crate) buffered_bytes: usize,
    pub(crate) window_opened: Arc<Notify>,
    pub(crate) app_tx: Option<mpsc::Sender<Bytes>>,
    pub(crate) termination: Arc<crate::stream::termination::Termination>,
    pub(crate) highest_rx_offset: u64,
    pub(crate) final_rx_offset: Option<u64>,
    pub(crate) send_stopped_error: Option<u64>,
    pub(crate) last_sent_max_data: u64,
    /// Timestamp of the last auto-tuning flow control window check/update.
    pub(crate) last_window_update: std::time::Instant,
    /// Total bytes consumed by the application from the stream within the current auto-tuning epoch.
    pub(crate) bytes_read_in_epoch: usize,
    #[allow(dead_code)]
    pub(crate) stream_type: StreamType,
}

impl StreamState {
    pub(crate) fn new(
        app_tx: mpsc::Sender<Bytes>,
        window_opened: Arc<Notify>,
        stream_type: StreamType,
        receive_window: u64,
        transmit_window: u64,
        termination: Arc<crate::stream::termination::Termination>,
    ) -> Self {
        let window_size = receive_window;
        Self {
            expected_rx_offset: 0,
            next_tx_offset: 0,
            receive_buffer: StreamReceiveBuffer::new(window_size as usize),
            window_size,
            tx_window: transmit_window,
            buffered_bytes: 0,
            window_opened,
            app_tx: Some(app_tx),
            termination,
            highest_rx_offset: 0,
            final_rx_offset: None,
            send_stopped_error: None,
            last_sent_max_data: window_size,
            last_window_update: std::time::Instant::now(),
            bytes_read_in_epoch: 0,
            stream_type,
        }
    }

    pub(crate) fn signal_window_opened(&self) {
        // Wake current waiters and leave one stored permit for a waiter that
        // races with this signal after the actor sends its response.
        self.window_opened.notify_waiters();
        self.window_opened.notify_one();
    }
}
