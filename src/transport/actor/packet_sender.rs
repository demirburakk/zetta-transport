use super::ZtConnectionActor;
use crate::error::{Result, ZtError};
use crate::protocol::frame::Frame;
use crate::protocol::packet::{PacketHeader, PacketType};
use crate::transport::stream_state::{ConnectionState, UnackedPacket, UnackedPayload};
use bytes::{BufMut, Bytes, BytesMut};
use ed25519_dalek::Signer;
use sha2::Digest;
use std::io::IoSlice;
use std::time::{Duration, Instant as StdInstant};

const KEY_UPDATE_PACKET_INTERVAL: u64 = 1 << 20;

impl ZtConnectionActor {
    fn note_packet_sent(&mut self) {
        if self.state.state != ConnectionState::Active {
            return;
        }
        let Some(crypto) = self.state.crypto.as_mut() else {
            return;
        };
        self.state.packets_since_key_update =
            self.state.packets_since_key_update.saturating_add(1);
        if self.state.packets_since_key_update >= KEY_UPDATE_PACKET_INTERVAL {
            crypto.rotate_keys();
            self.state.current_key_epoch = self.state.current_key_epoch.saturating_add(1);
            self.state.packets_since_key_update = 0;
        }
    }

    #[cfg(unix)]
    pub(super) fn sendmsg_vectored(&mut self, iov: &[IoSlice]) -> Result<()> {
        let total_len: usize = iov.iter().map(|s| s.len()).sum();
        if !self.is_client
            && self.state.state == ConnectionState::Handshaking
            && self.state.bytes_sent + total_len > 3 * self.state.bytes_received.max(1)
        {
            tracing::warn!("Amplification limit reached, dropping packet");
            return Ok(());
        }
        use libc::{c_void, iovec, msghdr, sendmsg, sockaddr_in, sockaddr_in6};
        use std::os::unix::io::AsRawFd;
        let fd = self.socket.as_raw_fd();
        let mut msg: msghdr = unsafe { std::mem::zeroed() };
        let mut iovecs: Vec<iovec> = iov
            .iter()
            .map(|s| iovec {
                iov_base: s.as_ptr() as *mut c_void,
                iov_len: s.len(),
            })
            .collect();
        msg.msg_iov = iovecs.as_mut_ptr();
        msg.msg_iovlen = iovecs.len() as _;
        let mut addr_v4: sockaddr_in = unsafe { std::mem::zeroed() };
        let mut addr_v6: sockaddr_in6 = unsafe { std::mem::zeroed() };
        match self.state.addr {
            std::net::SocketAddr::V4(v4) => {
                addr_v4.sin_family = libc::AF_INET as _;
                addr_v4.sin_port = v4.port().to_be();
                addr_v4.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
                msg.msg_name = &mut addr_v4 as *mut _ as *mut c_void;
                msg.msg_namelen = std::mem::size_of::<sockaddr_in>() as _;
            }
            std::net::SocketAddr::V6(v6) => {
                addr_v6.sin6_family = libc::AF_INET6 as _;
                addr_v6.sin6_port = v6.port().to_be();
                addr_v6.sin6_addr.s6_addr = v6.ip().octets();
                msg.msg_name = &mut addr_v6 as *mut _ as *mut c_void;
                msg.msg_namelen = std::mem::size_of::<sockaddr_in6>() as _;
            }
        }
        let res = unsafe { sendmsg(fd, &msg, 0) };
        if res < 0 {
            let err = std::io::Error::last_os_error();
            tracing::debug!("Failed to send vectored: {}", err);
            return Err(ZtError::Io(err));
        } else {
            self.state.bytes_sent += total_len;
        }
        Ok(())
    }

    #[cfg(not(unix))]
    pub(super) fn sendmsg_vectored(&mut self, iov: &[IoSlice]) -> Result<()> {
        let mut buf = Vec::new();
        for slice in iov {
            buf.extend_from_slice(slice);
        }
        self.send_to_socket(&buf)
    }

    #[cfg(not(unix))]
    fn send_to_socket(&mut self, packet: &[u8]) -> Result<()> {
        if self.state.state == ConnectionState::Handshaking
            && self.state.bytes_sent + packet.len() > 3 * self.state.bytes_received.max(1)
        {
            return Ok(());
        }
        if let Err(e) = self.socket.try_send_to(packet, self.state.addr) {
            tracing::debug!("Failed to send: {}", e);
            return Err(ZtError::Io(e));
        } else {
            self.state.bytes_sent += packet.len();
        }
        Ok(())
    }

    pub(super) fn send_mtu_probe(&mut self) -> Result<()> {
        if self.state.state != ConnectionState::Active {
            return Ok(());
        }
        let probe_sizes = [1200, 1350, 1400, 1450, 1500];
        let target_size = probe_sizes
            .iter()
            .copied()
            .find(|&s| s > self.state.mtu)
            .unwrap_or(self.state.mtu + 50);
        if target_size > 1500 {
            return Ok(());
        }
        let pn = self.state.get_next_packet_number()?;
        let key_phase = self.current_key_phase();
        let total_buffered = self.state.get_total_buffered_bytes();
        self.state.local_window = (1024u32 * 1024u32).saturating_sub(total_buffered as u32);
        let lowest_unacked = self.state.unacked_packets.keys().next().unwrap_or(pn);
        let (_, pn_len) =
            crate::protocol::packet_number::truncate_pn(pn, lowest_unacked.saturating_sub(1));
        let header = PacketHeader {
            p_type: PacketType::MtuProbe,
            is_long: false,
            version: 0,
            dcid: self.state.dcid.clone(),
            scid: vec![],
            packet_number: pn,
            key_phase,
            pn_len,
        };
        let mut packet = BytesMut::with_capacity(target_size + 32);
        header.encode(&mut packet);
        let header_len = packet.len();
        let frame = Frame::Padding(target_size.saturating_sub(header_len + 16));
        frame.encode(&mut packet);
        let payload_len = packet.len() - header_len;
        packet.put_bytes(0, 16);
        let crypto = self.state.crypto.as_mut().ok_or(ZtError::Unauthorized)?;
        {
            let ps = packet.as_mut();
            let (aad, rest) = ps.split_at_mut(header_len);
            let (payload, tag_space) = rest.split_at_mut(payload_len);
            let tag = crypto.encrypt_in_place(pn, aad, payload)?;
            tag_space.copy_from_slice(&tag);
        }
        let ps = packet.as_mut();
        if let Some(offset) = PacketHeader::get_pn_offset(ps) {
            crypto.apply_header_protection(ps, offset)?;
        }
        let sent_bytes = packet.len();
        if let Err(e) = self.sendmsg_vectored(&[IoSlice::new(packet.as_ref())]) {
            tracing::debug!("Failed to send MTU probe: {}", e);
            return Ok(());
        }
        self.state.unacked_packets.insert(
            pn,
            UnackedPacket {
                payload: UnackedPayload::MtuProbe { target_size },
                sent_at: StdInstant::now(),
                retries: 0,
                is_mtu_probe: true,
                sent_bytes,
            },
        );
        self.state.mtu_probes.insert(pn, target_size);
        self.note_packet_sent();
        Ok(())
    }

    pub(super) fn flush_acks(&mut self) -> Result<()> {
        if self.pending_acks == 0 {
            return Ok(());
        }
        let pn = self.state.get_next_packet_number()?;
        let kp = self.current_key_phase();
        self.state.local_window =
            (1024u32 * 1024u32).saturating_sub(self.state.get_total_buffered_bytes() as u32);
        let lowest_unacked = self.state.unacked_packets.keys().next().unwrap_or(pn);
        let (_, pn_len) =
            crate::protocol::packet_number::truncate_pn(pn, lowest_unacked.saturating_sub(1));
        let header = PacketHeader {
            p_type: PacketType::Data,
            is_long: false,
            version: 0,
            dcid: self.state.dcid.clone(),
            scid: vec![],
            packet_number: pn,
            key_phase: kp,
            pn_len,
        };
        let mut packet = BytesMut::with_capacity(128);
        header.encode(&mut packet);
        let header_len = packet.len();
        let ack_ranges = self.state.get_ack_ranges();
        Frame::Ack {
            largest_acked: self.state.ack_tracker.highest_processed.unwrap_or(0),
            window_size: self.state.local_window,
            ack_ranges,
        }
        .encode(&mut packet);
        let payload_len = packet.len() - header_len;
        packet.put_bytes(0, 16);
        let crypto = self.state.crypto.as_mut().ok_or(ZtError::Unauthorized)?;
        {
            let p = packet.as_mut();
            let (aad, rest) = p.split_at_mut(header_len);
            let (payload, tag_space) = rest.split_at_mut(payload_len);
            let tag = crypto.encrypt_in_place(pn, aad, payload)?;
            tag_space.copy_from_slice(&tag);
        }
        if let Some(offset) = PacketHeader::get_pn_offset(packet.as_mut()) {
            crypto.apply_header_protection(packet.as_mut(), offset)?;
        }
        if let Err(e) = self.sendmsg_vectored(&[IoSlice::new(&packet)]) {
            tracing::warn!("Failed to flush acks: {}", e);
        } else {
            self.note_packet_sent();
        }
        self.pending_acks = 0;
        Ok(())
    }

    pub(super) fn process_outgoing_data(&mut self, stream_id: u32, data: Bytes) -> Result<()> {
        let to_send_len = data.len() as u32;

        // Check global flow control
        if self.state.remote_window < to_send_len {
            return Err(ZtError::FlowControlBlocked);
        }

        // Check stream flow control
        let stream = self.state.streams.get_mut(&stream_id).ok_or(ZtError::ActorFailed)?;
        if stream.tx_window < to_send_len as u64 {
            return Err(ZtError::FlowControlBlocked);
        }

        let to_send_len_usize = to_send_len as usize;
        let queued_bytes = self.state.queued_bytes;
        
        if self.state.bytes_in_flight + to_send_len_usize + queued_bytes > self.state.cwnd {
            return Err(ZtError::CongestionWindowFull);
        }

        let start = stream.next_tx_offset;
        stream.next_tx_offset += to_send_len as u64;
        stream.tx_window -= to_send_len as u64;
        self.state.conn_tx_offset =
            self.state.conn_tx_offset.saturating_add(to_send_len as u64);
        
        self.state.remote_window -= to_send_len;
        
        let payload_len = data.len();
        let payload = UnackedPayload::Stream {
            stream_id,
            offset: start,
            data,
        };
        self.state.unpaced_queue.push_back(payload);
        self.state.queued_bytes += payload_len;
        Ok(())
    }

    pub(super) fn flush_pacing_queue(&mut self) -> Option<std::time::Duration> {
        let now = StdInstant::now();
        let rate = self.state.cwnd as f64 / self.state.rtt.as_secs_f64().max(0.001);
        if let Some(last) = self.state.last_pacing_update {
            let elapsed = now.duration_since(last).as_secs_f64();
            self.state.pacing_tokens += rate * elapsed;
            let max_burst = (self.state.mtu * 10) as f64;
            if self.state.pacing_tokens > max_burst {
                self.state.pacing_tokens = max_burst;
            }
        } else {
            self.state.last_pacing_update = Some(now);
        }
        self.state.last_pacing_update = Some(now);

        while let Some(payload) = self.state.unpaced_queue.front() {
            let len = payload.len() as f64;
            let payload_len = payload.len();
            if self.state.pacing_tokens >= len {
                let p = self.state.unpaced_queue.pop_front().unwrap();
                self.state.queued_bytes = self.state.queued_bytes.saturating_sub(payload_len);
                self.state.pacing_tokens -= len;
                if let Err(e) = self.send_payload(p) {
                    tracing::debug!("Failed to send paced payload: {}", e);
                }
            } else {
                let deficit = len - self.state.pacing_tokens;
                let wait_secs = deficit / rate;
                return Some(std::time::Duration::from_secs_f64(wait_secs));
            }
        }
        None
    }

    pub(super) fn handle_retransmits(&mut self) -> Result<()> {
        let now = StdInstant::now();
        let rto = (self.state.rtt + self.state.rttvar * 4).max(Duration::from_millis(50));
        let mut to_retransmit = std::collections::HashSet::new();
        let mut to_drop = Vec::new();
        for (pn, up) in self.state.unacked_packets.iter_mut() {
            if now.duration_since(up.sent_at) > rto {
                if up.is_mtu_probe {
                    to_drop.push(pn);
                } else if up.retries > 10 {
                    to_drop.push(pn);
                } else {
                    up.retries += 1;
                    if up.retries > 3 {
                        self.state.mtu = 1200; // MTU Fallback
                    }
                    up.sent_at = now;
                    to_drop.push(pn);
                    to_retransmit.insert(pn);
                }
            }
        }
        let total_unacked = self.state.unacked_packets.len();

        let mut payloads_to_resend = Vec::new();
        for pn in to_drop {
            if let Some(up) = self.state.unacked_packets.remove(pn) {
                self.state.bytes_in_flight =
                    self.state.bytes_in_flight.saturating_sub(up.sent_bytes);
                if up.is_mtu_probe {
                    self.state.mtu_probes.remove(&pn);
                } else if to_retransmit.contains(&pn) {
                    payloads_to_resend.push(up.payload);
                }
            }
        }

        if !payloads_to_resend.is_empty() {
            self.state.handle_loss();
            for payload in payloads_to_resend {
                if let Err(e) = self.retransmit_payload(payload) {
                    tracing::warn!("Failed to retransmit: {}", e);
                }
            }
        }

        if total_unacked > 0 && to_retransmit.is_empty() && self.state.unacked_packets.is_empty() {
            return Err(ZtError::Timeout);
        }
        Ok(())
    }

    pub(crate) fn retransmit_payload(&mut self, payload: UnackedPayload) -> Result<()> {
        self.send_payload(payload)
    }

    fn send_payload(&mut self, payload: UnackedPayload) -> Result<()> {
        let pn = self.state.get_next_packet_number()?;
        let kp = self.current_key_phase();
        let lowest_unacked = self.state.unacked_packets.keys().next().unwrap_or(pn);
        let (_, pn_len) =
            crate::protocol::packet_number::truncate_pn(pn, lowest_unacked.saturating_sub(1));
        let header = PacketHeader {
            p_type: PacketType::Data,
            is_long: false,
            version: 0,
            dcid: self.state.dcid.clone(),
            scid: vec![],
            packet_number: pn,
            key_phase: kp,
            pn_len,
        };

        let mut packet = BytesMut::with_capacity(payload.len() + 128);
        header.encode(&mut packet);
        let h_len = packet.len();

        match &payload {
            UnackedPayload::Stream {
                stream_id,
                offset,
                data,
            } => {
                Frame::Stream {
                    id: *stream_id,
                    offset: *offset,
                    data: data.clone(),
                }
                .encode(&mut packet);
            }
            UnackedPayload::MtuProbe { target_size } => {
                Frame::Padding(target_size.saturating_sub(h_len + 16)).encode(&mut packet);
            }
            UnackedPayload::StreamClose { stream_id } => {
                Frame::StreamClose { id: *stream_id }.encode(&mut packet);
            }
            UnackedPayload::MaxStreamData { stream_id, max_data } => {
                Frame::MaxStreamData { id: *stream_id, max_data: *max_data }.encode(&mut packet);
            }
            UnackedPayload::Close => {
                Frame::ConnectionClose.encode(&mut packet);
            }
        }

        let p_len = packet.len() - h_len;
        packet.put_bytes(0, 16);
        let crypto = self.state.crypto.as_mut().ok_or(ZtError::Unauthorized)?;
        {
            let p = packet.as_mut();
            let (aad, rest) = p.split_at_mut(h_len);
            let (payload_space, tag_space) = rest.split_at_mut(p_len);
            let tag = crypto.encrypt_in_place(pn, aad, payload_space)?;
            tag_space.copy_from_slice(&tag);
        }
        if let Some(offset) = PacketHeader::get_pn_offset(packet.as_mut()) {
            crypto.apply_header_protection(packet.as_mut(), offset)?;
        }
        let frozen = packet.freeze();
        let packet_len = frozen.len();

        self.sendmsg_vectored(&[IoSlice::new(&frozen)])?;
        let is_mtu_probe = matches!(payload, UnackedPayload::MtuProbe { .. });
        self.state.unacked_packets.insert(
            pn,
            UnackedPacket {
                payload,
                sent_at: StdInstant::now(),
                retries: 0,
                is_mtu_probe,
                sent_bytes: packet_len,
            },
        );
        self.state.bytes_in_flight += packet_len;
        self.note_packet_sent();

        Ok(())
    }

    pub(super) fn send_stream_close(&mut self, stream_id: u32) -> Result<()> {
        self.send_payload(UnackedPayload::StreamClose { stream_id })
    }

    pub(super) fn initiate_close(&mut self) -> Result<()> {
        self.state.state = ConnectionState::Closing;
        self.send_payload(UnackedPayload::Close)
    }

    pub(super) fn send_initial_packet(&mut self, cookie: Option<bytes::Bytes>) -> Result<()> {
        let pn = self.state.get_next_packet_number()?;
        let lowest_unacked = self.state.unacked_packets.keys().next().unwrap_or(pn);
        let (_, pn_len) =
            crate::protocol::packet_number::truncate_pn(pn, lowest_unacked.saturating_sub(1));
        let h = PacketHeader {
            p_type: PacketType::Initial,
            is_long: true,
            version: 1,
            dcid: self.state.dcid.clone(),
            scid: self.state.scid.clone(),
            packet_number: pn,
            key_phase: false,
            pn_len,
        };
        let mut p = BytesMut::with_capacity(1200);
        h.encode(&mut p);
        let h_len = p.len();

        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, &1u32.to_be_bytes());
        sha2::Digest::update(&mut hasher, &self.state.scid);
        sha2::Digest::update(&mut hasher, &self.state.dcid);
        sha2::Digest::update(&mut hasher, self.public_key.as_bytes());
        if let Some(ref c) = cookie {
            self.state.cookie = Some(c.clone());
            sha2::Digest::update(&mut hasher, c);
        }
        let transcript_hash = sha2::Digest::finalize(hasher).to_vec();

        Frame::Handshake {
            public_key: *self.public_key.as_bytes(),
            ed_public_key: *self.ed_public_key.as_bytes(),
            transcript_hash: transcript_hash.clone(),
            signature: self.ed_signing_key.sign(&transcript_hash).to_bytes(),
        }
        .encode(&mut p);
        if let Some(c) = cookie {
            Frame::Cookie { cookie: c }.encode(&mut p);
        }
        let pad_len = 1200usize.saturating_sub(p.len() + 16);
        if pad_len > 0 {
            Frame::Padding(pad_len).encode(&mut p);
        }
        let p_len = p.len() - h_len;
        p.put_bytes(0, 16);
        let crypto = crate::crypto::CryptoContext::initial(&self.state.dcid, true);
        {
            let s = p.as_mut();
            let (aad, rest) = s.split_at_mut(h_len);
            let (payload, tag) = rest.split_at_mut(p_len);
            let t = crypto.encrypt_in_place(pn, aad, payload)?;
            tag.copy_from_slice(&t);
        }
        if let Some(offset) = PacketHeader::get_pn_offset(p.as_mut()) {
            crypto.apply_header_protection(p.as_mut(), offset)?;
        }
        if let Err(e) = self.sendmsg_vectored(&[IoSlice::new(p.as_ref())]) {
            tracing::debug!("Initial send error: {}", e);
        }
        Ok(())
    }
}
