use crate::error::{Result, ZtError};
use bytes::{Buf, BufMut, Bytes, BytesMut};

#[derive(Debug, Clone, PartialEq)]
pub enum Frame {
    Padding(usize),
    Stream {
        id: u32,
        offset: u64,
        data: Bytes,
    },
    Ack {
        largest_acked: u64,
        window_size: u32,
    },
    ConnectionClose,
    Handshake {
        public_key: [u8; 32],
        ed_public_key: [u8; 32],
        signature: [u8; 64],
    },
    Cookie {
        cookie: Bytes,
    },
}

impl Frame {
    pub fn encode(&self, dst: &mut BytesMut) {
        match self {
            Frame::Padding(len) => {
                for _ in 0..*len {
                    dst.put_u8(0x00);
                }
            }
            Frame::Stream { id, offset, data } => {
                dst.put_u8(0x01);
                dst.put_u32(*id);
                dst.put_u64(*offset);
                dst.put_u16(data.len() as u16);
                dst.put_slice(data);
            }
            Frame::Ack { largest_acked, window_size } => {
                dst.put_u8(0x02);
                dst.put_u64(*largest_acked);
                dst.put_u32(*window_size);
            }
            Frame::ConnectionClose => {
                dst.put_u8(0x03);
            }
            Frame::Handshake { public_key, ed_public_key, signature } => {
                dst.put_u8(0x04);
                dst.put_slice(public_key);
                dst.put_slice(ed_public_key);
                dst.put_slice(signature);
            }
            Frame::Cookie { cookie } => {
                dst.put_u8(0x05);
                dst.put_u16(cookie.len() as u16);
                dst.put_slice(cookie);
            }
        }
    }

    pub fn decode(src: &mut Bytes) -> Result<Self> {
        if src.remaining() < 1 {
            return Err(ZtError::InvalidPacket("Empty frame".into()));
        }

        let frame_type = src.get_u8();
        match frame_type {
            0x00 => {
                let mut padding_len = 1;
                while src.remaining() > 0 && src.chunk()[0] == 0x00 {
                    src.advance(1);
                    padding_len += 1;
                }
                Ok(Frame::Padding(padding_len))
            }
            0x01 => {
                if src.remaining() < 14 {
                    return Err(ZtError::InvalidPacket("Stream frame too short".into()));
                }
                let id = src.get_u32();
                let offset = src.get_u64();
                let len = src.get_u16() as usize;
                if src.remaining() < len {
                    return Err(ZtError::InvalidPacket("Stream frame truncated".into()));
                }
                let data = src.copy_to_bytes(len);
                Ok(Frame::Stream { id, offset, data })
            }
            0x02 => {
                if src.remaining() < 12 {
                    return Err(ZtError::InvalidPacket("Ack frame too short".into()));
                }
                let largest_acked = src.get_u64();
                let window_size = src.get_u32();
                Ok(Frame::Ack { largest_acked, window_size })
            }
            0x03 => Ok(Frame::ConnectionClose),
            0x04 => {
                if src.remaining() < 128 {
                    return Err(ZtError::InvalidPacket("Handshake frame too short".into()));
                }
                let mut public_key = [0u8; 32];
                public_key.copy_from_slice(&src.chunk()[..32]);
                src.advance(32);
                let mut ed_public_key = [0u8; 32];
                ed_public_key.copy_from_slice(&src.chunk()[..32]);
                src.advance(32);
                let mut signature = [0u8; 64];
                signature.copy_from_slice(&src.chunk()[..64]);
                src.advance(64);
                Ok(Frame::Handshake { public_key, ed_public_key, signature })
            }
            0x05 => {
                if src.remaining() < 2 {
                    return Err(ZtError::InvalidPacket("Cookie frame too short".into()));
                }
                let len = src.get_u16() as usize;
                if src.remaining() < len {
                    return Err(ZtError::InvalidPacket("Cookie frame truncated".into()));
                }
                let cookie = src.copy_to_bytes(len);
                Ok(Frame::Cookie { cookie })
            }
            _ => Err(ZtError::InvalidPacket(format!("Unknown frame type: {}", frame_type))),
        }
    }
}
