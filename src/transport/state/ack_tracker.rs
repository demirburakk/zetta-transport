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

#[cfg(test)]
mod tests {
    use super::AckTracker;

    #[test]
    fn ack_tracker_sequential() {
        let mut t = AckTracker::new();
        for pn in 0..10u64 {
            t.mark_processed(pn);
        }
        let ranges = t.get_ack_ranges();
        assert_eq!(ranges, vec![(0, 9)]);
    }

    #[test]
    fn ack_tracker_with_gap() {
        let mut t = AckTracker::new();
        for pn in [0u64, 1, 2, 5, 6, 7] {
            t.mark_processed(pn);
        }
        let ranges = t.get_ack_ranges();
        assert_eq!(ranges.len(), 2);
        assert!(ranges.contains(&(5, 7)));
        assert!(ranges.contains(&(0, 2)));
    }

    #[test]
    fn ack_tracker_out_of_order() {
        let mut t = AckTracker::new();
        t.mark_processed(10);
        t.mark_processed(5);
        t.mark_processed(8);
        let ranges = t.get_ack_ranges();
        assert!(ranges.contains(&(10, 10)));
        assert!(ranges.contains(&(8, 8)));
        assert!(ranges.contains(&(5, 5)));
    }

    #[test]
    fn ack_tracker_duplicate_ignored() {
        let mut t = AckTracker::new();
        t.mark_processed(5);
        t.mark_processed(5);
        let ranges = t.get_ack_ranges();
        assert_eq!(ranges, vec![(5, 5)]);
    }

    #[test]
    fn ack_tracker_window_overflow_resets() {
        let mut t = AckTracker::new();
        t.mark_processed(0);
        t.mark_processed(3000);
        let ranges = t.get_ack_ranges();
        assert_eq!(ranges, vec![(3000, 3000)]);
    }
}
