use crate::error::{Result, ZtError};
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// Packet types for wire-level headers.
///
/// Long-header types: Initial (0x00), Handshake (0x01), Retry (0x0C).
/// Short-header types: Data (0x02), Close (0x0A), MtuProbe (0x0B).
///
/// These discriminants overlap with Frame type bytes (0x00–0x08) at the
/// byte level, but they occupy **separate parsing contexts**: packet type
/// is extracted from the header's first byte (bits [5:2]), while frame
/// types are parsed from the decrypted payload stream. The gap between
/// short-header types (0x0A+) and frame types (≤0x08) provides an extra
/// safety margin against mis-parsing corrupted data.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PacketType {
    Initial = 0x00,
    Handshake = 0x01,
    Data = 0x02,
    Close = 0x0A,
    MtuProbe = 0x0B,
    Retry = 0x0C,
}

#[derive(Debug)]
pub struct PacketHeader {
    pub p_type: PacketType,
    pub is_long: bool,
    pub version: u32,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    pub packet_number: u64,
    pub key_phase: bool,
    pub pn_len: usize,
}

impl PacketHeader {
    pub(crate) fn get_pn_offset(data: &[u8]) -> Option<usize> {
        if data.is_empty() {
            return None;
        }
        let is_long = (data[0] & 0x80) != 0;
        if is_long {
            let mut offset = 6;
            if data.len() < offset {
                return None;
            }
            let dcid_len = data[5] as usize;
            offset += dcid_len;
            if data.len() < offset + 1 {
                return None;
            }
            let scid_len = data[offset] as usize;
            offset += 1 + scid_len;
            Some(offset)
        } else {
            let mut offset = 2;
            if data.len() < offset {
                return None;
            }
            let dcid_len = data[1] as usize;
            offset += dcid_len;
            Some(offset)
        }
    }

    pub(crate) fn encode(&self, dst: &mut BytesMut) {
        let pn_len = self.pn_len.clamp(1, 4);
        let len_bits = (pn_len - 1) as u8;
        let mask = match pn_len {
            1 => 0xFF,
            2 => 0xFFFF,
            3 => 0xFFFFFF,
            4 => 0xFFFFFFFF,
            _ => 0xFFFFFFFF,
        };
        let truncated_pn = (self.packet_number & mask) as u32;

        if self.is_long {
            let first_byte = 0x80 | ((self.p_type as u8 & 0x0F) << 2) | len_bits;
            dst.put_u8(first_byte);
            dst.put_u32(self.version);
            dst.put_u8(self.dcid.len() as u8);
            dst.put_slice(&self.dcid);
            dst.put_u8(self.scid.len() as u8);
            dst.put_slice(&self.scid);
        } else {
            let mut first_byte = ((self.p_type as u8 & 0x0F) << 2) | len_bits;
            if self.key_phase {
                first_byte |= 0x40;
            }
            dst.put_u8(first_byte);
            dst.put_u8(self.dcid.len() as u8);
            dst.put_slice(&self.dcid);
        }

        match pn_len {
            1 => dst.put_u8(truncated_pn as u8),
            2 => dst.put_u16(truncated_pn as u16),
            3 => {
                let bytes = truncated_pn.to_be_bytes();
                dst.put_slice(&bytes[1..4]);
            }
            4 => dst.put_u32(truncated_pn),
            _ => unreachable!(),
        }
    }

    pub(crate) fn decode(src: &mut Bytes) -> Result<Self> {
        if src.remaining() < 1 {
            return Err(ZtError::InvalidPacket("Empty buffer".into()));
        }
        let first_byte = src.get_u8();
        let is_long = (first_byte & 0x80) != 0;
        let pn_len = (first_byte & 0x03) as usize + 1;
        let p_type_val = (first_byte >> 2) & 0x0F;

        if is_long {
            let p_type = match p_type_val {
                0x00 => PacketType::Initial,
                0x01 => PacketType::Handshake,
                0x0C => PacketType::Retry,
                _ => return Err(ZtError::InvalidPacket("Invalid long packet type".into())),
            };
            if src.remaining() < 5 + pn_len {
                return Err(ZtError::InvalidPacket("Short".into()));
            }
            let version = src.get_u32();
            let dcid_len = src.get_u8() as usize;
            if src.remaining() < dcid_len {
                return Err(ZtError::InvalidPacket("Truncated DCID".into()));
            }
            let dcid = src.copy_to_bytes(dcid_len).to_vec();
            if src.remaining() < 1 {
                return Err(ZtError::InvalidPacket("Missing SCID len".into()));
            }
            let scid_len = src.get_u8() as usize;
            if src.remaining() < scid_len + pn_len {
                return Err(ZtError::InvalidPacket("Truncated".into()));
            }
            let scid = src.copy_to_bytes(scid_len).to_vec();

            let truncated_pn = match pn_len {
                1 => src.get_u8() as u64,
                2 => src.get_u16() as u64,
                3 => {
                    let mut b = [0u8; 4];
                    src.copy_to_slice(&mut b[1..4]);
                    u32::from_be_bytes(b) as u64
                }
                4 => src.get_u32() as u64,
                _ => unreachable!(),
            };

            Ok(Self {
                p_type,
                is_long,
                version,
                dcid,
                scid,
                packet_number: truncated_pn,
                key_phase: false,
                pn_len,
            })
        } else {
            let key_phase = (first_byte & 0x40) != 0;
            let p_type = match p_type_val {
                0x02 => PacketType::Data,
                0x0A => PacketType::Close,
                0x0B => PacketType::MtuProbe,
                _ => return Err(ZtError::InvalidPacket("Invalid short packet type".into())),
            };
            if src.remaining() < 1 + pn_len {
                return Err(ZtError::InvalidPacket("Short".into()));
            }
            let dcid_len = src.get_u8() as usize;
            if src.remaining() < dcid_len + pn_len {
                return Err(ZtError::InvalidPacket("Truncated".into()));
            }
            let dcid = src.copy_to_bytes(dcid_len).to_vec();

            let truncated_pn = match pn_len {
                1 => src.get_u8() as u64,
                2 => src.get_u16() as u64,
                3 => {
                    let mut b = [0u8; 4];
                    src.copy_to_slice(&mut b[1..4]);
                    u32::from_be_bytes(b) as u64
                }
                4 => src.get_u32() as u64,
                _ => unreachable!(),
            };

            Ok(Self {
                p_type,
                is_long,
                version: 0,
                dcid,
                scid: vec![],
                packet_number: truncated_pn,
                key_phase,
                pn_len,
            })
        }
    }
}
