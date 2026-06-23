use crate::transport::state::StreamReceiveBuffer;
use bytes::Bytes;
use std::sync::Arc;
use tokio::sync::{Notify, mpsc};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamType {
    Bidirectional,
    UnidirectionalOut,
    UnidirectionalIn,
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
    pub(crate) app_tx: mpsc::Sender<Bytes>,
    pub(crate) last_sent_max_data: u64,
    /// Timestamp of the last auto-tuning flow control window check/update.
    pub(crate) last_window_update: std::time::Instant,
    /// Total bytes consumed by the application from the stream within the current auto-tuning epoch.
    pub(crate) bytes_read_in_epoch: usize,
    pub(crate) stream_type: StreamType,
}

impl StreamState {
    pub(crate) fn new(app_tx: mpsc::Sender<Bytes>, window_opened: Arc<Notify>, stream_type: StreamType) -> Self {
        let window_size = 1024 * 1024;
        Self {
            expected_rx_offset: 0,
            next_tx_offset: 0,
            receive_buffer: StreamReceiveBuffer::new(window_size as usize),
            window_size,
            tx_window: 1024 * 1024,
            buffered_bytes: 0,
            window_opened,
            app_tx,
            last_sent_max_data: window_size,
            last_window_update: std::time::Instant::now(),
            bytes_read_in_epoch: 0,
            stream_type,
        }
    }
}
