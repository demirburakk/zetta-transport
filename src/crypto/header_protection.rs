use crate::error::{Result, ZtError};
use aes::Aes128;
use aes::cipher::{BlockCipherEncrypt, KeyInit};

/// Applies header protection to a packet in-place.
pub(crate) fn apply_header_protection(
    packet: &mut [u8],
    pn_offset: usize,
    tx_hp_key: &[u8; 32],
) -> Result<()> {
    let sample_offset = pn_offset + 4; // Sample starts 4 bytes after PN field
    if packet.len() < sample_offset + 16 {
        return Ok(());
    }

    let mut sample = [0u8; 16];
    sample.copy_from_slice(&packet[sample_offset..sample_offset + 16]);

    let cipher = Aes128::new_from_slice(&tx_hp_key[..16])
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

    let cipher = Aes128::new_from_slice(&hp_key[..16])
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
