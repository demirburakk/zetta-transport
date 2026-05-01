use crate::error::{Result, ZtError};
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// Frame types for ZettaTransport payloads.
/// Note: Frame types and Packet types exist in separate namespaces.
/// E.g., Frame::StreamClose (0x06) is distinct from PacketType::MtuProbe (0x06).
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
        ack_ranges: Vec<(u64, u64)>,
    },
    ConnectionClose,
    Handshake {
        public_key: [u8; 32],
        ed_public_key: [u8; 32],
        transcript_hash: Vec<u8>,
        signature: [u8; 64],
    },
    Cookie {
        cookie: Bytes,
    },
    StreamClose {
        id: u32,
    },
}

impl Frame {
    pub(crate) fn encode(&self, dst: &mut BytesMut) {
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
            Frame::Ack {
                largest_acked,
                window_size,
                ack_ranges,
            } => {
                dst.put_u8(0x02);
                dst.put_u64(*largest_acked);
                dst.put_u32(*window_size);
                dst.put_u8(ack_ranges.len() as u8);
                for (start, end) in ack_ranges {
                    dst.put_u64(*start);
                    dst.put_u64(*end);
                }
            }
            Frame::ConnectionClose => {
                dst.put_u8(0x03);
            }
            Frame::Handshake {
                public_key,
                ed_public_key,
                transcript_hash,
                signature,
            } => {
                dst.put_u8(0x04);
                dst.put_slice(public_key);
                dst.put_slice(ed_public_key);
                dst.put_u16(transcript_hash.len() as u16);
                dst.put_slice(transcript_hash);
                dst.put_slice(signature);
            }
            Frame::Cookie { cookie } => {
                dst.put_u8(0x05);
                dst.put_u16(cookie.len() as u16);
                dst.put_slice(cookie);
            }
            Frame::StreamClose { id } => {
                dst.put_u8(0x06);
                dst.put_u32(*id);
            }
        }
    }

    pub(crate) fn decode(src: &mut Bytes) -> Result<Self> {
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
                let range_count = if src.remaining() > 0 { src.get_u8() } else { 0 } as usize;

                if src.remaining() < range_count * 16 {
                    return Err(ZtError::InvalidPacket("Ack frame ranges truncated".into()));
                }
                let mut ack_ranges = Vec::with_capacity(range_count);
                for _ in 0..range_count {
                    let start = src.get_u64();
                    let end = src.get_u64();
                    ack_ranges.push((start, end));
                }
                Ok(Frame::Ack {
                    largest_acked,
                    window_size,
                    ack_ranges,
                })
            }
            0x03 => Ok(Frame::ConnectionClose),
            0x04 => {
                if src.remaining() < 130 {
                    return Err(ZtError::InvalidPacket("Handshake frame too short".into()));
                }
                let mut public_key = [0u8; 32];
                public_key.copy_from_slice(&src.chunk()[..32]);
                src.advance(32);
                let mut ed_public_key = [0u8; 32];
                ed_public_key.copy_from_slice(&src.chunk()[..32]);
                src.advance(32);
                let th_len = src.get_u16() as usize;
                if src.remaining() < th_len + 64 {
                    return Err(ZtError::InvalidPacket("Handshake frame truncated".into()));
                }
                let transcript_hash = src.copy_to_bytes(th_len).to_vec();
                let mut signature = [0u8; 64];
                signature.copy_from_slice(&src.chunk()[..64]);
                src.advance(64);
                Ok(Frame::Handshake {
                    public_key,
                    ed_public_key,
                    transcript_hash,
                    signature,
                })
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
            0x06 => {
                if src.remaining() < 4 {
                    return Err(ZtError::InvalidPacket("StreamClose frame too short".into()));
                }
                let id = src.get_u32();
                Ok(Frame::StreamClose { id })
            }
            _ => Err(ZtError::InvalidPacket(format!(
                "Unknown frame type: {}",
                frame_type
            ))),
        }
    }
}
