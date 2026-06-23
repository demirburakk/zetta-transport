pub(crate) fn truncate_pn(pn: u64, largest_acked: u64) -> (u32, usize) {
    let unacked = pn.saturating_sub(largest_acked);
    // The packet number size must represent more than twice the unacked range.
    let num_bits = 64 - (unacked * 2).leading_zeros();

    let mut pn_len = (num_bits as usize).div_ceil(8);
    if pn_len == 0 {
        pn_len = 1;
    }
    if pn_len > 4 {
        pn_len = 4;
    }

    let mask = match pn_len {
        1 => 0xFF,
        2 => 0xFFFF,
        3 => 0xFFFFFF,
        4 => 0xFFFFFFFF,
        _ => unreachable!(),
    };

    ((pn & mask) as u32, pn_len)
}

pub(crate) fn expand_pn(pn_truncated: u64, pn_len: usize, largest_pn: u64) -> u64 {
    let pn_nbits = pn_len * 8;
    let expected_pn = largest_pn.saturating_add(1);
    let pn_win = 1u64 << pn_nbits;
    let pn_hwin = pn_win / 2;
    let pn_mask = pn_win - 1;

    let candidate_pn = (expected_pn & !pn_mask) | pn_truncated;

    if expected_pn >= pn_hwin && candidate_pn <= expected_pn - pn_hwin {
        candidate_pn.saturating_add(pn_win)
    } else if expected_pn.checked_add(pn_hwin).map_or(false, |limit| candidate_pn > limit)
        && candidate_pn >= pn_win
    {
        candidate_pn.saturating_sub(pn_win)
    } else {
        candidate_pn
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_expand_roundtrip() {
        let cases = [
            (0u64, 0u64),
            (1, 0),
            (255, 0),
            (256, 0),
            (1000, 900),
            (u32::MAX as u64, u32::MAX as u64 - 100),
            (u64::MAX / 2, u64::MAX / 2 - 1),
        ];
        for (pn, largest_acked) in cases {
            let (truncated, len) = truncate_pn(pn, largest_acked);
            let expanded = expand_pn(truncated as u64, len, largest_acked);
            assert_eq!(expanded, pn, "pn={pn}, largest_acked={largest_acked}");
        }
    }

    #[test]
    fn expand_pn_out_of_order() {
        let expanded = expand_pn(98, 1, 99);
        assert_eq!(expanded, 98);
    }

    #[test]
    fn expand_pn_wraparound_u8() {
        let expanded = expand_pn(0, 1, 254);
        assert_eq!(expanded, 256);
    }
    
    #[test]
    fn fuzz_packet_numbers() {
        // Pseudo-fuzzing with edge cases and random leaps
        let mut largest_acked = 0;
        for i in 1..100_000 {
            let step = (i % 250) as u64; // leap up to 250
            let pn = largest_acked + step;
            let (truncated, len) = truncate_pn(pn, largest_acked);
            let expanded = expand_pn(truncated as u64, len, largest_acked);
            assert_eq!(expanded, pn, "Failed to expand step {step} from {largest_acked} (len {len}, trunc {truncated})");
            
            // Advance largest acked arbitrarily occasionally
            if i % 10 == 0 {
                largest_acked = pn;
            }
        }
    }
}
