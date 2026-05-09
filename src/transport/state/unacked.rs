use bytes::Bytes;
use std::time::Instant;

/// Describes the content of an unacknowledged packet.
pub(crate) enum UnackedPayload {
    Stream {
        stream_id: u32,
        offset: u64,
        data: Bytes,
    },
    MtuProbe {
        target_size: usize,
    },
    StreamClose {
        stream_id: u32,
    },
    MaxStreamData {
        stream_id: u32,
        max_data: u64,
    },
    Close,
    Initial {
        cookie: Option<Bytes>,
    },
    Handshake {
        public_key: [u8; 32],
        ed_public_key: [u8; 32],
        transcript_hash: Vec<u8>,
        signature: [u8; 64],
    },
}

impl UnackedPayload {
    pub(crate) fn len(&self) -> usize {
        match self {
            UnackedPayload::Stream { data, .. } => data.len(),
            UnackedPayload::MtuProbe { target_size } => *target_size,
            UnackedPayload::StreamClose { .. }
            | UnackedPayload::MaxStreamData { .. }
            | UnackedPayload::Close
            | UnackedPayload::Initial { .. }
            | UnackedPayload::Handshake { .. } => 0,
        }
    }
}

/// A packet that has been sent but not yet acknowledged.
pub(crate) struct UnackedPacket {
    pub(crate) payload: UnackedPayload,
    pub(crate) sent_at: Instant,
    pub(crate) retries: u32,
    pub(crate) is_mtu_probe: bool,
    pub(crate) sent_bytes: usize,
}
