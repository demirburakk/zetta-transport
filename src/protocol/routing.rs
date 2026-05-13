/// Extracts the Destination Connection ID from a raw packet buffer
/// without fully parsing the header.
///
/// This is a fast-path helper used by the router to dispatch incoming
/// datagrams to the correct per-connection actor.
pub(crate) fn extract_dcid_fast(data: &[u8]) -> Option<Vec<u8>> {
    if data.is_empty() {
        return None;
    }
    let is_long = (data[0] & 0x80) != 0;

    if is_long {
        if data.len() < 6 {
            return None;
        }
        let dcid_len = data[5] as usize;
        if data.len() < 6 + dcid_len {
            return None;
        }
        Some(data[6..6 + dcid_len].to_vec())
    } else {
        if data.len() < 2 {
            return None;
        }
        let dcid_len = data[1] as usize;
        if data.len() < 2 + dcid_len {
            return None;
        }
        Some(data[2..2 + dcid_len].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::extract_dcid_fast;

    #[test]
    fn extract_dcid_short_header() {
        let data = [0x02u8, 3, 1, 2, 3, 0xAA, 0xBB];
        let dcid = extract_dcid_fast(&data).expect("dcid missing");
        assert_eq!(dcid, vec![1, 2, 3]);
    }

    #[test]
    fn extract_dcid_long_header() {
        let data = vec![0x80u8, 0, 0, 0, 1, 4, 9, 8, 7, 6, 2, 1, 2];
        let dcid = extract_dcid_fast(&data).expect("dcid missing");
        assert_eq!(dcid, vec![9, 8, 7, 6]);
    }

    #[test]
    fn extract_dcid_empty_or_truncated() {
        assert!(extract_dcid_fast(&[]).is_none());
        assert!(extract_dcid_fast(&[0x80u8, 0, 0, 0, 1]).is_none());
        assert!(extract_dcid_fast(&[0x02u8]).is_none());
        let truncated_long = [0x80u8, 0, 0, 0, 1, 5, 1, 2, 3, 4];
        assert!(extract_dcid_fast(&truncated_long).is_none());
    }
}
