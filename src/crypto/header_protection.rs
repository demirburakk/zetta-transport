use crate::error::{Result, ZtError};
use chacha20::{ChaCha20, cipher::{KeyIvInit, StreamCipher}};

/// Applies header protection to a packet in-place using ChaCha20.
pub(crate) fn apply_header_protection(
    packet: &mut [u8],
    pn_offset: usize,
    tx_hp_key: &[u8; 32],
) -> Result<()> {
    let sample_offset = pn_offset + 4; // Sample starts 4 bytes after PN field
    if packet.len() < sample_offset + 16 {
        return Err(ZtError::InvalidPacket(
            "Packet too short to apply header protection".into(),
        ));
    }

    let mut sample = [0u8; 16];
    sample.copy_from_slice(&packet[sample_offset..sample_offset + 16]);

    // For ChaCha20 header protection: counter = sample[0..4], nonce = sample[4..16]
    let counter = u32::from_le_bytes(sample[0..4].try_into().unwrap());
    
    let mut cipher = ChaCha20::new_from_slices(tx_hp_key, &sample[4..16]).unwrap();
    use chacha20::cipher::StreamCipherSeek;
    cipher.seek(counter as u64 * 64);

    let mut mask = [0u8; 5];
    cipher.apply_keystream(&mut mask);

    let is_long = (packet[0] & 0x80) != 0;
    let pn_len = (packet[0] & 0x03) as usize + 1;
    let first_mask = mask[0] & if is_long { 0x0F } else { 0x1F };
    packet[0] ^= first_mask;

    for i in 0..pn_len {
        if pn_offset + i < packet.len() {
            packet[pn_offset + i] ^= mask[i + 1];
        }
    }

    Ok(())
}

/// Removes header protection from a received packet in-place using ChaCha20.
pub(crate) fn remove_header_protection(
    packet: &mut [u8],
    pn_offset: usize,
    hp_key: &[u8; 32],
) -> Result<()> {
    let sample_offset = pn_offset + 4;
    if sample_offset + 16 > packet.len() {
        return Err(ZtError::InvalidPacket(
            "Packet too short to remove header protection".into(),
        ));
    }

    let mut sample = [0u8; 16];
    sample.copy_from_slice(&packet[sample_offset..sample_offset + 16]);

    let counter = u32::from_le_bytes(sample[0..4].try_into().unwrap());
    
    let mut cipher = ChaCha20::new_from_slices(hp_key, &sample[4..16]).unwrap();
    use chacha20::cipher::StreamCipherSeek;
    cipher.seek(counter as u64 * 64);

    let mut mask = [0u8; 5];
    cipher.apply_keystream(&mut mask);

    let is_long = (packet[0] & 0x80) != 0;
    let first_mask = mask[0] & if is_long { 0x0F } else { 0x1F };
    packet[0] ^= first_mask;

    let pn_len = (packet[0] & 0x03) as usize + 1;

    for i in 0..pn_len {
        if pn_offset + i < packet.len() {
            packet[pn_offset + i] ^= mask[i + 1];
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_packet() -> Vec<u8> {
        let mut p = vec![0u8; 30];
        p[0] = 0x08;
        p[1] = 0;
        p
    }

    #[test]
    fn header_protection_roundtrip() {
        let hp_key = [0xABu8; 32];
        let pn_offset = 2;
        let mut packet = make_test_packet();
        let original = packet.clone();

        apply_header_protection(&mut packet, pn_offset, &hp_key).unwrap();
        assert_ne!(packet[0], original[0]);
        assert_ne!(packet[pn_offset], original[pn_offset]);

        remove_header_protection(&mut packet, pn_offset, &hp_key).unwrap();
        assert_eq!(packet, original);
    }

    #[test]
    fn apply_hp_short_packet_errors() {
        let hp_key = [0u8; 32];
        let mut too_short = vec![0u8; 10];
        too_short[0] = 0x08;
        too_short[1] = 0;
        let result = apply_header_protection(&mut too_short, 2, &hp_key);
        assert!(result.is_err());
    }

    #[test]
    fn remove_hp_short_packet_errors() {
        let hp_key = [0u8; 32];
        let mut too_short = vec![0u8; 10];
        too_short[0] = 0x08;
        too_short[1] = 0;
        let result = remove_header_protection(&mut too_short, 2, &hp_key);
        assert!(result.is_err());
    }

    #[test]
    fn long_header_mask_bits() {
        let hp_key = [0xFFu8; 32];
        let pn_offset = 6;
        let mut packet = vec![0xAAu8; 30];
        packet[0] = 0x80;
        let original_first = packet[0];
        apply_header_protection(&mut packet, pn_offset, &hp_key).unwrap();
        assert_eq!(packet[0] & 0xF0, original_first & 0xF0);
    }
}

