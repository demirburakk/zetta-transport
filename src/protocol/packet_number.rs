pub(crate) fn truncate_pn(pn: u64, largest_acked: u64) -> (u32, usize) {
    let unacked = pn.saturating_sub(largest_acked);
    let num_bits = 64 - unacked.leading_zeros();

    let mut pn_len = (num_bits + 7) / 8;
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

    ((pn & mask) as u32, pn_len as usize)
}

pub(crate) fn expand_pn(pn_truncated: u64, pn_len: usize, largest_pn: u64) -> u64 {
    let pn_nbits = pn_len * 8;
    let expected_pn = largest_pn + 1;
    let pn_win = 1u64 << pn_nbits;
    let pn_hwin = pn_win / 2;
    let pn_mask = pn_win - 1;

    let candidate_pn = (expected_pn & !pn_mask) | pn_truncated;

    if candidate_pn + pn_hwin <= expected_pn {
        candidate_pn + pn_win
    } else if candidate_pn > expected_pn + pn_hwin && candidate_pn >= pn_win {
        candidate_pn - pn_win
    } else {
        candidate_pn
    }
}
