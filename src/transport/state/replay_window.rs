/// A 2048-packet replay protection bitmask window.
///
/// This window tracks the highest packet number processed and uses a 2048-bit
/// sliding window (represented as `[u64; 32]`) to track out-of-order packets.
/// 
/// - If a packet is received that is older than `highest_processed - 2048`, it is
///   considered too old and automatically rejected as a potential replay attack.
/// - The 2048-packet size is chosen to be large enough to accommodate significant 
///   packet reordering on high bandwidth-delay product networks without falsely 
///   rejecting valid but delayed packets, while bounding memory usage securely.
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

#[cfg(test)]
mod tests {
    use super::ReplayWindow;

    #[test]
    fn replay_window_no_replay_initially() {
        let w = ReplayWindow::new();
        assert!(!w.is_replay(0));
        assert!(!w.is_replay(100));
    }

    #[test]
    fn replay_window_detects_replay() {
        let mut w = ReplayWindow::new();
        w.mark_processed(5);
        assert!(w.is_replay(5));
    }

    #[test]
    fn replay_window_too_old_is_replay() {
        let mut w = ReplayWindow::new();
        w.mark_processed(3000);
        assert!(w.is_replay(0));
    }

    #[test]
    fn replay_window_future_is_not_replay() {
        let mut w = ReplayWindow::new();
        w.mark_processed(5);
        assert!(!w.is_replay(6));
    }
}
