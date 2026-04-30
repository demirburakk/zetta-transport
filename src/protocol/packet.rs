use crate::error::{Result, ZtError};
use bytes::{Buf, BufMut, Bytes, BytesMut};

pub const MAX_PACKET_SIZE: usize = 1450;

/// Packet types for ZettaTransport.
/// Note: Packet types and Frame types exist in separate namespaces.
/// E.g., PacketType::MtuProbe (0x06) is distinct from Frame::StreamClose (0x06).
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PacketType {
    Initial = 0x00,
    Handshake = 0x01,
    Data = 0x02,
    Close = 0x05,
    MtuProbe = 0x06,
    Retry = 0x07,
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
}

impl PacketHeader {
    pub fn get_pn_offset(data: &[u8]) -> Option<usize> {
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

    pub fn encode(&self, dst: &mut BytesMut) {
        if self.is_long {
            let first_byte = 0x80 | (self.p_type as u8);
            dst.put_u8(first_byte);
            dst.put_u32(self.version);
            dst.put_u8(self.dcid.len() as u8);
            dst.put_slice(&self.dcid);
            dst.put_u8(self.scid.len() as u8);
            dst.put_slice(&self.scid);
            dst.put_u64(self.packet_number);
        } else {
            let mut first_byte = self.p_type as u8 & 0x3F;
            if self.key_phase {
                first_byte |= 0x40; // Set Key Phase bit
            }
            dst.put_u8(first_byte);
            dst.put_u8(self.dcid.len() as u8);
            dst.put_slice(&self.dcid);
            dst.put_u64(self.packet_number);
        }
    }

    pub fn decode(src: &mut Bytes) -> Result<Self> {
        if src.remaining() < 1 {
            return Err(ZtError::InvalidPacket("Empty buffer".into()));
        }

        let first_byte = src.get_u8();
        let is_long = (first_byte & 0x80) != 0;

        if is_long {
            let p_type_val = first_byte & 0x0F;
            let p_type = match p_type_val {
                0x00 => PacketType::Initial,
                0x01 => PacketType::Handshake,
                0x02 => PacketType::Data,
                0x07 => PacketType::Retry,
                _ => return Err(ZtError::InvalidPacket("Invalid long packet type".into())),
            };

            if src.remaining() < 14 {
                return Err(ZtError::InvalidPacket(
                    "Packet too short for long header".into(),
                ));
            }

            let version = src.get_u32();

            let dcid_len = src.get_u8() as usize;
            if src.remaining() < dcid_len {
                return Err(ZtError::InvalidPacket("Truncated DCID".into()));
            }
            let dcid = src.copy_to_bytes(dcid_len).to_vec();

            if src.remaining() < 1 {
                return Err(ZtError::InvalidPacket("Missing SCID length".into()));
            }
            let scid_len = src.get_u8() as usize;
            if src.remaining() < scid_len + 8 {
                return Err(ZtError::InvalidPacket(
                    "Truncated SCID or missing PN".into(),
                ));
            }
            let scid = src.copy_to_bytes(scid_len).to_vec();
            let packet_number = src.get_u64();

            Ok(Self {
                p_type,
                is_long,
                version,
                dcid,
                scid,
                packet_number,
                key_phase: false,
            })
        } else {
            let key_phase = (first_byte & 0x40) != 0;
            let p_type_val = first_byte & 0x3F;
            let p_type = match p_type_val {
                0x02 => PacketType::Data,
                0x05 => PacketType::Close,
                0x06 => PacketType::MtuProbe,
                _ => return Err(ZtError::InvalidPacket("Invalid short packet type".into())),
            };

            if src.remaining() < 9 {
                return Err(ZtError::InvalidPacket(
                    "Packet too short for short header".into(),
                ));
            }

            let dcid_len = src.get_u8() as usize;
            if src.remaining() < dcid_len + 8 {
                return Err(ZtError::InvalidPacket(
                    "Truncated DCID or missing PN".into(),
                ));
            }
            let dcid = src.copy_to_bytes(dcid_len).to_vec();
            let packet_number = src.get_u64();

            Ok(Self {
                p_type,
                is_long,
                version: 0,
                dcid,
                scid: vec![],
                packet_number,
                key_phase,
            })
        }
    }
}
