use crate::error::{Result, ZtError};
use aes::Aes128;
use aes::cipher::{BlockCipherEncrypt, KeyInit};

/// Applies header protection to a packet in-place.
pub(crate) fn apply_header_protection(
    packet: &mut [u8],
    pn_offset: usize,
    tx_hp_key: &[u8; 16],
) -> Result<()> {
    let sample_offset = pn_offset + 4; // Sample starts 4 bytes after PN field
    if packet.len() < sample_offset + 16 {
        return Err(ZtError::InvalidPacket(
            "Packet too short to apply header protection".into(),
        ));
    }

    let mut sample = [0u8; 16];
    sample.copy_from_slice(&packet[sample_offset..sample_offset + 16]);

    let cipher = Aes128::new_from_slice(tx_hp_key)
        .map_err(|_| ZtError::Crypto("Invalid HP key length".into()))?;

    let mut block = aes::Block::from(sample);
    cipher.encrypt_block(&mut block);
    let mask = block.as_slice();

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

/// Removes header protection from a received packet in-place.
pub(crate) fn remove_header_protection(
    packet: &mut [u8],
    pn_offset: usize,
    hp_key: &[u8; 16],
) -> Result<()> {
    let sample_offset = pn_offset + 4;
    if sample_offset + 16 > packet.len() {
        return Err(ZtError::InvalidPacket(
            "Packet too short to remove header protection".into(),
        ));
    }

    let mut sample = [0u8; 16];
    sample.copy_from_slice(&packet[sample_offset..sample_offset + 16]);

    let cipher = Aes128::new_from_slice(hp_key)
        .map_err(|_| ZtError::Crypto("Invalid HP key length".into()))?;

    let mut block = aes::Block::from(sample);
    cipher.encrypt_block(&mut block);
    let mask = block.as_slice();

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
        let hp_key = [0xABu8; 16];
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
        let hp_key = [0u8; 16];
        let mut too_short = vec![0u8; 10];
        too_short[0] = 0x08;
        too_short[1] = 0;
        let result = apply_header_protection(&mut too_short, 2, &hp_key);
        assert!(result.is_err());
    }

    #[test]
    fn remove_hp_short_packet_errors() {
        let hp_key = [0u8; 16];
        let mut too_short = vec![0u8; 10];
        too_short[0] = 0x08;
        too_short[1] = 0;
        let result = remove_header_protection(&mut too_short, 2, &hp_key);
        assert!(result.is_err());
    }

    #[test]
    fn long_header_mask_bits() {
        let hp_key = [0xFFu8; 16];
        let pn_offset = 6;
        let mut packet = vec![0xFFu8; 30];
        packet[0] = 0x80;
        let original_first = packet[0];
        apply_header_protection(&mut packet, pn_offset, &hp_key).unwrap();
        assert_eq!(packet[0] & 0xF0, original_first & 0xF0);
    }
}
