use bytes::{Bytes, BytesMut};
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

/// A pre-allocated circular buffer for receiving out-of-order stream data.
pub(crate) struct StreamReceiveBuffer {
    buffer: Vec<u8>,
    pub(crate) read_head: u64,
    pub(crate) write_head: u64,
    /// List of received ranges (start, end)
    pub(crate) received_ranges: Vec<std::ops::Range<u64>>,
}

impl StreamReceiveBuffer {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            buffer: vec![0; capacity],
            read_head: 0,
            write_head: 0,
            received_ranges: Vec::new(),
        }
    }

    pub(crate) fn write(&mut self, offset: u64, data: &[u8]) -> bool {
        if data.is_empty() {
            return true;
        }
        let end_offset = offset + data.len() as u64;
        
        // Cannot fit in the buffer
        if end_offset > self.read_head + self.buffer.len() as u64 {
            return false;
        }

        if end_offset > self.write_head {
            self.write_head = end_offset;
        }

        let cap = self.buffer.len() as u64;
        for (i, &b) in data.iter().enumerate() {
            let pos = (offset + i as u64) % cap;
            self.buffer[pos as usize] = b;
        }

        self.add_range(offset..end_offset);
        true
    }

    fn add_range(&mut self, mut new_range: std::ops::Range<u64>) {
        let mut i = 0;
        while i < self.received_ranges.len() {
            let r = &self.received_ranges[i];
            if new_range.start <= r.end && r.start <= new_range.end {
                // Merge
                new_range.start = std::cmp::min(new_range.start, r.start);
                new_range.end = std::cmp::max(new_range.end, r.end);
                self.received_ranges.remove(i);
            } else {
                i += 1;
            }
        }
        self.received_ranges.push(new_range);
        self.received_ranges.sort_by_key(|r| r.start);
    }

    pub(crate) fn read_contiguous(&mut self) -> Option<Bytes> {
        if self.received_ranges.is_empty() {
            return None;
        }
        
        if self.received_ranges[0].start <= self.read_head && self.received_ranges[0].end > self.read_head {
            let end = self.received_ranges[0].end;
            let len = (end - self.read_head) as usize;
            
            let mut out = BytesMut::with_capacity(len);
            let cap = self.buffer.len() as u64;
            
            let start_idx = (self.read_head % cap) as usize;
            let end_idx = ((self.read_head + len as u64) % cap) as usize;

            if start_idx < end_idx {
                out.extend_from_slice(&self.buffer[start_idx..end_idx]);
            } else {
                out.extend_from_slice(&self.buffer[start_idx..]);
                out.extend_from_slice(&self.buffer[..end_idx]);
            }
            
            self.read_head = end;
            
            // Clean up old ranges
            self.received_ranges.retain(|r| r.end > self.read_head);
            if !self.received_ranges.is_empty() && self.received_ranges[0].start < self.read_head {
                 self.received_ranges[0].start = self.read_head;
            }
            
            return Some(out.freeze());
        }
        None
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
    MaxStreamData {
        stream_id: u32,
        max_data: u64,
    },
    Close,
}

impl UnackedPayload {
    pub(crate) fn len(&self) -> usize {
        match self {
            UnackedPayload::Stream { data, .. } => data.len(),
            UnackedPayload::MtuProbe { target_size } => *target_size,
            UnackedPayload::StreamClose { .. } | UnackedPayload::MaxStreamData { .. } | UnackedPayload::Close => 0,
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
