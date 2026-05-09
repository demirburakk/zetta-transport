use crate::transport::state::StreamReceiveBuffer;
use bytes::Bytes;
use std::sync::Arc;
use tokio::sync::{Notify, mpsc};

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
}

impl StreamState {
    pub(crate) fn new(app_tx: mpsc::Sender<Bytes>, window_opened: Arc<Notify>) -> Self {
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
        }
    }
}
