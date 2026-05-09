use crate::error::{Result, ZtError};
use bytes::{Buf, BufMut, Bytes, BytesMut};

/// Frame types for ZettaTransport payloads.
///
/// Frame type discriminants occupy bytes 0x00–0x08. PacketType discriminants
/// use the 0x0A+ range, so there is no byte-level collision between the two
/// namespaces.
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
    MaxStreamData {
        id: u32,
        max_data: u64,
    },
    MaxData {
        max_data: u64,
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
                let range_len = ack_ranges.len().min(128);
                dst.put_u8(range_len as u8);
                for (start, end) in ack_ranges.iter().take(range_len) {
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
            Frame::MaxStreamData { id, max_data } => {
                dst.put_u8(0x07);
                dst.put_u32(*id);
                dst.put_u64(*max_data);
            }
            Frame::MaxData { max_data } => {
                dst.put_u8(0x08);
                dst.put_u64(*max_data);
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
                if src.remaining() < 13 {
                    return Err(ZtError::InvalidPacket("Ack frame too short".into()));
                }
                let largest_acked = src.get_u64();
                let window_size = src.get_u32();
                let range_count = src.get_u8() as usize;
                if range_count > 128 {
                    return Err(ZtError::InvalidPacket("Too many ACK ranges".into()));
                }

                if src.remaining() < range_count * 16 {
                    return Err(ZtError::InvalidPacket("Ack frame ranges truncated".into()));
                }
                let mut ack_ranges = Vec::with_capacity(range_count);
                for _ in 0..range_count {
                    let start = src.get_u64();
                    let end = src.get_u64();
                    if start > end {
                        return Err(ZtError::InvalidPacket(
                            "Ack range start > end".into(),
                        ));
                    }
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
            0x07 => {
                if src.remaining() < 12 {
                    return Err(ZtError::InvalidPacket("MaxStreamData frame too short".into()));
                }
                let id = src.get_u32();
                let max_data = src.get_u64();
                Ok(Frame::MaxStreamData { id, max_data })
            }
            0x08 => {
                if src.remaining() < 8 {
                    return Err(ZtError::InvalidPacket("MaxData frame too short".into()));
                }
                let max_data = src.get_u64();
                Ok(Frame::MaxData { max_data })
            }
            _ => Err(ZtError::InvalidPacket(format!(
                "Unknown frame type: {}",
                frame_type
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::{Bytes, BytesMut, BufMut};

    fn roundtrip(frame: Frame) -> Frame {
        let mut buf = BytesMut::new();
        frame.encode(&mut buf);
        let mut bytes = buf.freeze();
        Frame::decode(&mut bytes).expect("decode failed")
    }

    #[test]
    fn stream_frame_roundtrip() {
        let f = Frame::Stream {
            id: 42,
            offset: 1000,
            data: Bytes::from_static(b"hello world"),
        };
        assert_eq!(roundtrip(f.clone()), f);
    }

    #[test]
    fn ack_frame_roundtrip_with_ranges() {
        let f = Frame::Ack {
            largest_acked: 500,
            window_size: 65536,
            ack_ranges: vec![(400, 450), (480, 499)],
        };
        assert_eq!(roundtrip(f.clone()), f);
    }

    #[test]
    fn ack_frame_rejects_invalid_range() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x02);
        buf.put_u64(100u64);
        buf.put_u32(65536u32);
        buf.put_u8(1u8);
        buf.put_u64(50u64);
        buf.put_u64(10u64);
        let mut bytes = buf.freeze();
        assert!(Frame::decode(&mut bytes).is_err());
    }

    #[test]
    fn decode_truncated_stream_frame_errors() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x01);
        buf.put_u32(1u32);
        let mut bytes = buf.freeze();
        assert!(Frame::decode(&mut bytes).is_err());
    }

    #[test]
    fn ack_range_count_limit() {
        let mut buf = BytesMut::new();
        buf.put_u8(0x02);
        buf.put_u64(200u64);
        buf.put_u32(65536u32);
        buf.put_u8(129u8);
        for i in 0..129u64 {
            buf.put_u64(i * 2);
            buf.put_u64(i * 2 + 1);
        }
        let mut bytes = buf.freeze();
        assert!(Frame::decode(&mut bytes).is_err());
    }
}
