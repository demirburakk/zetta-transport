use crate::transport::state::UnackedPacket;
use std::collections::VecDeque;

/// A sliding window ring buffer for tracking unacknowledged packets.
/// Provides O(1) access by sequence number and avoids BTreeMap overhead.
pub(crate) struct UnackedWindow {
    pub(crate) base_pn: u64,
    pub(crate) deque: VecDeque<Option<UnackedPacket>>,
    len: usize,
}

impl UnackedWindow {
    pub fn new() -> Self {
        Self {
            base_pn: 0,
            deque: VecDeque::new(),
            len: 0,
        }
    }

    pub fn insert(&mut self, pn: u64, packet: UnackedPacket) {
        if self.len == 0 && self.deque.is_empty() {
            self.base_pn = pn;
        }
        if pn < self.base_pn {
            return;
        }
        let idx = (pn - self.base_pn) as usize;
        if idx >= self.deque.len() {
            self.deque.resize_with(idx + 1, || None);
        }
        if self.deque[idx].is_none() {
            self.len += 1;
        }
        self.deque[idx] = Some(packet);
    }

    pub fn remove(&mut self, pn: u64) -> Option<UnackedPacket> {
        if pn < self.base_pn {
            return None;
        }
        let idx = (pn - self.base_pn) as usize;
        if let Some(slot) = self.deque.get_mut(idx) {
            let val = slot.take();
            if val.is_some() {
                self.len -= 1;
            }
            while let Some(None) = self.deque.front() {
                self.deque.pop_front();
                self.base_pn += 1;
            }
            val
        } else {
            None
        }
    }

    pub fn clear(&mut self) {
        self.deque.clear();
        self.len = 0;
        self.base_pn = 0;
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.len
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[allow(dead_code)]
    pub fn get_mut(&mut self, pn: u64) -> Option<&mut UnackedPacket> {
        if pn < self.base_pn {
            return None;
        }
        let idx = (pn - self.base_pn) as usize;
        self.deque.get_mut(idx).and_then(|slot| slot.as_mut())
    }

    pub fn iter(&self) -> impl Iterator<Item = (u64, &UnackedPacket)> {
        let base_pn = self.base_pn;
        self.deque
            .iter()
            .enumerate()
            .filter_map(move |(i, opt)| opt.as_ref().map(|p| (base_pn + i as u64, p)))
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (u64, &mut UnackedPacket)> {
        let base_pn = self.base_pn;
        self.deque
            .iter_mut()
            .enumerate()
            .filter_map(move |(i, opt)| opt.as_mut().map(|p| (base_pn + i as u64, p)))
    }

    pub fn keys(&self) -> impl Iterator<Item = u64> + '_ {
        self.iter().map(|(pn, _)| pn)
    }
}

#[cfg(test)]
mod tests {
    use super::UnackedWindow;
    use crate::transport::state::{UnackedPacket, UnackedPayload};
    use bytes::Bytes;
    use std::time::Instant;

    fn make_packet() -> UnackedPacket {
        UnackedPacket {
            payload: UnackedPayload::Stream {
                stream_id: 0,
                offset: 0,
                data: Bytes::from_static(b"x"),
            },
            sent_at: Instant::now(),
            retries: 0,
            is_mtu_probe: false,
            sent_bytes: 1,
        }
    }

    #[test]
    fn insert_remove_shifts_base_forward() {
        let mut w = UnackedWindow::new();
        w.insert(10, make_packet());
        w.insert(11, make_packet());
        w.insert(12, make_packet());

        assert!(w.remove(10).is_some());
        let keys: Vec<u64> = w.keys().collect();
        assert_eq!(keys, vec![11, 12]);
    }

    #[test]
    fn insert_with_gap_preserves_keys() {
        let mut w = UnackedWindow::new();
        w.insert(5, make_packet());
        w.insert(7, make_packet());

        let keys: Vec<u64> = w.keys().collect();
        assert_eq!(keys, vec![5, 7]);

        assert!(w.remove(5).is_some());
        let keys: Vec<u64> = w.keys().collect();
        assert_eq!(keys, vec![7]);
    }

    #[test]
    fn remove_missing_keeps_len() {
        let mut w = UnackedWindow::new();
        w.insert(1, make_packet());

        assert!(w.remove(0).is_none());
        assert_eq!(w.len(), 1);
    }

    #[test]
    fn duplicate_insert_does_not_grow_len() {
        let mut w = UnackedWindow::new();
        w.insert(3, make_packet());
        w.insert(3, make_packet());
        assert_eq!(w.len(), 1);
    }
}
