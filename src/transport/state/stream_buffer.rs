use bytes::{Bytes, BytesMut};
use std::collections::BTreeMap;

/// A pre-allocated circular buffer for receiving out-of-order stream data.
///
/// Uses a `BTreeMap` for tracking received ranges instead of a sorted Vec,
/// providing O(log n) insertion and merge operations instead of O(n^2).
pub(crate) struct StreamReceiveBuffer {
    buffer: Vec<u8>,
    pub(crate) read_head: u64,
    pub(crate) write_head: u64,
    /// Received ranges keyed by start offset. Value is the end offset (exclusive).
    /// BTreeMap ensures O(log n) lookups and ordered iteration.
    received_ranges: BTreeMap<u64, u64>,
}

impl StreamReceiveBuffer {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            buffer: vec![0; capacity],
            read_head: 0,
            write_head: 0,
            received_ranges: BTreeMap::new(),
        }
    }

    pub(crate) fn write(&mut self, offset: u64, data: &[u8]) -> Option<usize> {
        if data.is_empty() {
            return Some(0);
        }
        let end_offset = offset + data.len() as u64;

        // Cannot fit in the buffer.
        if end_offset > self.read_head + self.buffer.len() as u64 {
            return None;
        }

        if end_offset > self.write_head {
            self.write_head = end_offset;
        }

        let cap = self.buffer.len() as u64;
        let start_idx = (offset % cap) as usize;
        let mut data_offset = 0;
        let mut write_idx = start_idx;

        while data_offset < data.len() {
            let chunk_len = std::cmp::min(data.len() - data_offset, self.buffer.len() - write_idx);
            self.buffer[write_idx..write_idx + chunk_len]
                .copy_from_slice(&data[data_offset..data_offset + chunk_len]);
            data_offset += chunk_len;
            write_idx = 0; // Wrap around for the next iteration.
        }

        let added = self.add_range(offset, end_offset);
        Some(added)
    }

    /// Inserts a range [start, end) into the BTreeMap and merges overlapping/adjacent ranges.
    /// Returns the number of new (non-overlapping) bytes added.
    fn add_range(&mut self, start: u64, end: u64) -> usize {
        let original_len = end - start;
        let mut merged_start = start;
        let mut merged_end = end;
        let mut overlap = 0u64;

        // Collect all ranges that overlap or are adjacent to [start, end).
        // A range (rs, re) overlaps if rs <= end && re >= start.
        let mut to_remove = Vec::new();

        // Check ranges starting at or before `end` that might overlap.
        // BTreeMap::range gives us efficient access.
        for (&rs, &re) in self.received_ranges.range(..=end) {
            if re >= start {
                // This range overlaps or is adjacent.
                let overlap_start = start.max(rs);
                let overlap_end = end.min(re);
                if overlap_end > overlap_start {
                    overlap += overlap_end - overlap_start;
                }
                merged_start = merged_start.min(rs);
                merged_end = merged_end.max(re);
                to_remove.push(rs);
            }
        }

        // Also check if there's a range starting just after `end` that's adjacent.
        if let Some((&rs, &re)) = self.received_ranges.range(end..).next() {
            if rs <= merged_end {
                merged_end = merged_end.max(re);
                to_remove.push(rs);
            }
        }

        for key in to_remove {
            self.received_ranges.remove(&key);
        }

        self.received_ranges.insert(merged_start, merged_end);
        original_len.saturating_sub(overlap) as usize
    }

    pub(crate) fn read_contiguous(&mut self) -> Option<Bytes> {
        // Check if the first range covers read_head.
        let (&first_start, &first_end) = self.received_ranges.iter().next()?;

        if first_start <= self.read_head && first_end > self.read_head {
            let len = (first_end - self.read_head) as usize;

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

            self.read_head = first_end;

            // Clean up old ranges.
            let stale_keys: Vec<u64> = self
                .received_ranges
                .range(..=self.read_head)
                .filter(|&(_, &end)| end <= self.read_head)
                .map(|(&k, _)| k)
                .collect();
            for key in stale_keys {
                self.received_ranges.remove(&key);
            }
            // Trim the first remaining range if it starts before read_head.
            if let Some((&rs, &re)) = self.received_ranges.iter().next() {
                if rs < self.read_head && re > self.read_head {
                    self.received_ranges.remove(&rs);
                    self.received_ranges.insert(self.read_head, re);
                }
            }

            return Some(out.freeze());
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::StreamReceiveBuffer;

    #[test]
    fn write_and_read_sequential() {
        let mut buf = StreamReceiveBuffer::new(4096);
        buf.write(0, b"hello").unwrap();
        let chunk = buf.read_contiguous().unwrap();
        assert_eq!(&chunk[..], b"hello");
        assert!(buf.read_contiguous().is_none());
    }

    #[test]
    fn out_of_order_delivery() {
        let mut buf = StreamReceiveBuffer::new(4096);
        buf.write(5, b"world").unwrap();
        assert!(buf.read_contiguous().is_none());
        buf.write(0, b"hello").unwrap();
        let chunk = buf.read_contiguous().unwrap();
        assert_eq!(&chunk[..], b"helloworld");
        assert!(buf.read_contiguous().is_none());
    }

    #[test]
    fn duplicate_write_handled() {
        let mut buf = StreamReceiveBuffer::new(4096);
        let added1 = buf.write(0, b"hello").unwrap();
        let added2 = buf.write(0, b"hello").unwrap();
        assert_eq!(added1, 5);
        assert_eq!(added2, 0);
        let chunk = buf.read_contiguous().unwrap();
        assert_eq!(&chunk[..], b"hello");
    }

    #[test]
    fn overlapping_write() {
        let mut buf = StreamReceiveBuffer::new(4096);
        buf.write(0, b"hello world").unwrap();
        buf.write(6, b"WORLD!!").unwrap();
        let chunk = buf.read_contiguous().unwrap();
        assert_eq!(chunk.len(), 13);
    }

    #[test]
    fn circular_wrap_around() {
        let mut buf = StreamReceiveBuffer::new(16);
        buf.write(0, b"0123456789abcdef").unwrap();
        let _ = buf.read_contiguous();
        buf.write(16, b"NEW_DATA").unwrap();
        let chunk = buf.read_contiguous().unwrap();
        assert_eq!(&chunk[..], b"NEW_DATA");
    }

    #[test]
    fn window_overflow_returns_none() {
        let mut buf = StreamReceiveBuffer::new(100);
        let result = buf.write(0, &vec![0u8; 101]);
        assert!(result.is_none());
    }

    #[test]
    fn buffered_ranges_merge_correctly() {
        let mut buf = StreamReceiveBuffer::new(4096);
        let added1 = buf.write(0, b"12345").unwrap();
        let added2 = buf.write(10, b"abcde").unwrap();
        assert_eq!(added1, 5);
        assert_eq!(added2, 5);
        let _ = buf.read_contiguous();
        let added3 = buf.write(5, b"67890").unwrap();
        assert_eq!(added3, 5);
        let chunk = buf.read_contiguous().unwrap();
        assert_eq!(chunk.len(), 10);
    }
}
