use crate::transport::stream_state::UnackedPacket;
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

    pub fn len(&self) -> usize {
        self.len
    }

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

/// A 2048-packet replay protection bitmask window.
pub(crate) struct ReplayWindow {
    pub highest_processed: Option<u64>,
    bitmask: [u64; 32], // 2048 bits
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            highest_processed: None,
            bitmask: [0; 32],
        }
    }

    pub fn is_replay(&self, pn: u64) -> bool {
        let Some(highest) = self.highest_processed else {
            return false;
        };
        if pn <= highest {
            let diff = highest - pn;
            if diff >= 2048 {
                return true;
            }
            let word_idx = (diff / 64) as usize;
            let bit_idx = diff % 64;
            return (self.bitmask[word_idx] & (1 << bit_idx)) != 0;
        }
        false
    }

    pub fn mark_processed(&mut self, pn: u64) {
        let Some(highest) = self.highest_processed else {
            self.highest_processed = Some(pn);
            self.bitmask[0] = 1;
            return;
        };

        if pn > highest {
            let diff = pn - highest;
            if diff >= 2048 {
                self.bitmask.fill(0);
                self.bitmask[0] = 1;
            } else {
                self.shift_left(diff as usize);
                self.bitmask[0] |= 1;
            }
            self.highest_processed = Some(pn);
        } else {
            let diff = highest - pn;
            if diff < 2048 {
                let word_idx = (diff / 64) as usize;
                let bit_idx = diff % 64;
                self.bitmask[word_idx] |= 1 << bit_idx;
            }
        }
    }

    fn shift_left(&mut self, shift: usize) {
        if shift == 0 {
            return;
        }
        if shift >= 2048 {
            self.bitmask.fill(0);
            return;
        }
        let word_shift = shift / 64;
        let bit_shift = shift % 64;

        if word_shift > 0 {
            for i in (word_shift..32).rev() {
                self.bitmask[i] = self.bitmask[i - word_shift];
            }
            for i in 0..word_shift {
                self.bitmask[i] = 0;
            }
        }

        if bit_shift > 0 {
            let inv_shift = 64 - bit_shift;
            for i in (1..32).rev() {
                self.bitmask[i] =
                    (self.bitmask[i] << bit_shift) | (self.bitmask[i - 1] >> inv_shift);
            }
            self.bitmask[0] <<= bit_shift;
        }
    }
}

/// Tracks successfully received and decrypted packets to generate SACK ranges.
pub(crate) struct AckTracker {
    pub highest_processed: Option<u64>,
    bitmask: [u64; 32], // 2048 bits
}

impl AckTracker {
    const MAX_ACK_RANGES: usize = 128;
    pub fn new() -> Self {
        Self {
            highest_processed: None,
            bitmask: [0; 32],
        }
    }

    pub fn mark_processed(&mut self, pn: u64) {
        let Some(highest) = self.highest_processed else {
            self.highest_processed = Some(pn);
            self.bitmask[0] = 1;
            return;
        };

        if pn > highest {
            let diff = pn - highest;
            if diff >= 2048 {
                self.bitmask.fill(0);
                self.bitmask[0] = 1;
            } else {
                self.shift_left(diff as usize);
                self.bitmask[0] |= 1;
            }
            self.highest_processed = Some(pn);
        } else {
            let diff = highest - pn;
            if diff < 2048 {
                let word_idx = (diff / 64) as usize;
                let bit_idx = diff % 64;
                self.bitmask[word_idx] |= 1 << bit_idx;
            }
        }
    }

    fn shift_left(&mut self, shift: usize) {
        if shift == 0 {
            return;
        }
        if shift >= 2048 {
            self.bitmask.fill(0);
            return;
        }
        let word_shift = shift / 64;
        let bit_shift = shift % 64;

        if word_shift > 0 {
            for i in (word_shift..32).rev() {
                self.bitmask[i] = self.bitmask[i - word_shift];
            }
            for i in 0..word_shift {
                self.bitmask[i] = 0;
            }
        }

        if bit_shift > 0 {
            let inv_shift = 64 - bit_shift;
            for i in (1..32).rev() {
                self.bitmask[i] =
                    (self.bitmask[i] << bit_shift) | (self.bitmask[i - 1] >> inv_shift);
            }
            self.bitmask[0] <<= bit_shift;
        }
    }

    pub fn get_ack_ranges(&self) -> Vec<(u64, u64)> {
        let mut ranges = Vec::new();
        let Some(highest) = self.highest_processed else {
            return ranges;
        };

        let mut in_range = false;
        let mut current_end = 0;
        let mut diff = 0u64;

        for &word in self.bitmask.iter() {
            if diff > highest {
                break;
            }
            if !in_range && word == 0 {
                diff += 64;
                continue;
            }
            if in_range && word == u64::MAX {
                diff += 64;
                continue;
            }

            let mut w = word;
            for _ in 0..64 {
                if diff > highest {
                    break;
                }
                let received = (w & 1) != 0;
                let pn = highest - diff;

                if received {
                    if !in_range {
                        in_range = true;
                        current_end = pn;
                    }
                } else if in_range {
                    ranges.push((pn + 1, current_end));
                    if ranges.len() >= Self::MAX_ACK_RANGES {
                        return ranges;
                    }
                    in_range = false;
                }

                w >>= 1;
                diff += 1;
            }
        }

        if in_range {
            let lowest = highest.saturating_sub(diff.saturating_sub(1));
            if ranges.len() < Self::MAX_ACK_RANGES {
                ranges.push((lowest, current_end));
            }
        }
        ranges
    }
}
