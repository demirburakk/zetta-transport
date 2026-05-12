use crate::transport::state::UnackedPacket;
use std::collections::VecDeque;

/// A sliding window ring buffer for tracking unacknowledged packets.
/// Provides O(1) access by sequence number and avoids BTreeMap overhead.
pub(crate) struct UnackedWindow {
    base_pn: u64,
    deque: VecDeque<Option<UnackedPacket>>,
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
