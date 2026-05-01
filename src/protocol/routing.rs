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
