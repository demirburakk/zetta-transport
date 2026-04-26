use crate::error::{Result, ZtError};
use bytes::{Buf, BufMut, Bytes, BytesMut};

pub const MAX_PACKET_SIZE: usize = 1450;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PacketType {
    Initial = 0x00,
    Handshake = 0x01,
    Data = 0x02,
    Ack = 0x03,
    Fec = 0x04,
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
    pub window_size: u32,
    pub stream_id: u32,
    pub offset: u64,
}

impl PacketHeader {
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
            let first_byte = self.p_type as u8 & 0x7F;
            dst.put_u8(first_byte);
            dst.put_u8(self.dcid.len() as u8);
            dst.put_slice(&self.dcid);
            dst.put_u64(self.packet_number);
            if self.p_type == PacketType::Ack {
                dst.put_u32(self.window_size);
            }
            if self.p_type == PacketType::Data {
                dst.put_u32(self.stream_id);
                dst.put_u64(self.offset);
            }
        }
    }

    pub fn decode(src: &mut Bytes) -> Result<Self> {
        if src.remaining() < 1 {
            return Err(ZtError::InvalidPacket("Empty buffer".into()));
        }

        let first_byte = src.get_u8();
        let is_long = (first_byte & 0x80) != 0;
        let p_type_val = first_byte & 0x0F;

        if is_long {
            let p_type = match p_type_val {
                0x00 => PacketType::Initial,
                0x01 => PacketType::Handshake,
                0x02 => PacketType::Data,
                0x03 => PacketType::Ack,
                0x04 => PacketType::Fec,
                0x07 => PacketType::Retry,
                _ => return Err(ZtError::InvalidPacket("Invalid long packet type".into())),
            };

            // BOUNDS CHECK: version(4) + dcid_len(1) + scid_len(1) + pn(8) = 14 bytes minimum
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
                window_size: 0,
                stream_id: 0,
                offset: 0,
            })
        } else {
            let p_type = match p_type_val {
                0x02 => PacketType::Data,
                0x03 => PacketType::Ack,
                0x04 => PacketType::Fec,
                0x05 => PacketType::Close,
                0x06 => PacketType::MtuProbe,
                _ => return Err(ZtError::InvalidPacket("Invalid short packet type".into())),
            };

            // BOUNDS CHECK: dcid_len(1) + pn(8) = 9 bytes minimum
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

            let mut window_size = 0;
            if p_type == PacketType::Ack {
                if src.remaining() < 4 {
                    return Err(ZtError::InvalidPacket("Missing window size in ACK".into()));
                }
                window_size = src.get_u32();
            }

            let mut stream_id = 0;
            let mut offset = 0;
            if p_type == PacketType::Data {
                if src.remaining() < 12 {
                    return Err(ZtError::InvalidPacket(
                        "Missing stream_id or offset in Data".into(),
                    ));
                }
                stream_id = src.get_u32();
                offset = src.get_u64();
            }

            Ok(Self {
                p_type,
                is_long,
                version: 0,
                dcid,
                scid: vec![],
                packet_number,
                window_size,
                stream_id,
                offset,
            })
        }
    }
}
