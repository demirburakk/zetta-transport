use crate::error::{Result, ZtError};
use crate::protocol::frame::Frame;
use crate::protocol::packet::{PacketHeader, PacketType};
use crate::stream::ZtStream;
use crate::transport::state::{ConnectionState, StreamState, UnackedPacket, ZtConnection};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use dashmap::DashMap;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::collections::BTreeMap;
use std::io::IoSlice;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant as StdInstant};
use tokio::net::UdpSocket;
use tokio::sync::{Notify, mpsc, oneshot};
use tokio::time::{Instant as TokioInstant, sleep_until};
use x25519_dalek::{PublicKey, StaticSecret};

pub enum ActorMessage {
    IncomingPacket {
        data: Bytes,
        addr: SocketAddr,
    },
    OutgoingData {
        stream_id: u32,
        data: Bytes,
        respond_to: oneshot::Sender<Result<()>>,
    },
    GetMtu {
        respond_to: oneshot::Sender<usize>,
    },
    CloseStream {
        stream_id: u32,
    },
    OpenStream {
        respond_to: oneshot::Sender<Result<ZtStream>>,
    },
    Close,
}

pub struct ZtConnectionActor {
    pub(crate) endpoint: Arc<crate::transport::endpoint::ZtEndpoint>,
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) receiver: mpsc::Receiver<ActorMessage>,
    pub(crate) state: ZtConnection,
    pub(crate) pending_acks: u32,
    pub(crate) public_key: PublicKey,
    pub(crate) static_secret: StaticSecret,
    pub(crate) ed_signing_key: SigningKey,
    pub(crate) ed_public_key: VerifyingKey,
    pub(crate) psk: Option<[u8; 32]>,
    pub(crate) handshake_waiter: Option<oneshot::Sender<()>>,
    pub(crate) routing_table: Arc<DashMap<Vec<u8>, mpsc::Sender<ActorMessage>>>,
    pub(crate) scid: Vec<u8>,
    pub(crate) last_active_stream_id: u32,
    pub(crate) incoming_streams_tx: mpsc::Sender<ZtStream>,
    pub(crate) next_stream_id: u32,
}

const SLEEP_FOREVER: Duration = Duration::from_secs(86400 * 365);

impl ZtConnectionActor {
    #[cfg(unix)]
    fn sendmsg_vectored(&mut self, iov: &[IoSlice]) -> Result<()> {
        let total_len: usize = iov.iter().map(|s| s.len()).sum();
        if self.state.state == ConnectionState::Handshaking
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
            SocketAddr::V4(v4) => {
                addr_v4.sin_family = libc::AF_INET as _;
                addr_v4.sin_port = v4.port().to_be();
                addr_v4.sin_addr.s_addr = u32::from_ne_bytes(v4.ip().octets());
                msg.msg_name = &mut addr_v4 as *mut _ as *mut c_void;
                msg.msg_namelen = std::mem::size_of::<sockaddr_in>() as _;
            }
            SocketAddr::V6(v6) => {
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
    fn sendmsg_vectored(&mut self, iov: &[IoSlice]) -> Result<()> {
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

    pub async fn run(mut self) {
        let mut rto_deadline = TokioInstant::now() + self.state.rtt;
        let mut idle_deadline = TokioInstant::now() + Duration::from_secs(60);
        let mut ack_deadline = TokioInstant::now() + SLEEP_FOREVER;
        let mut mtu_probe_deadline = TokioInstant::now() + Duration::from_secs(15);

        let rto_timer = sleep_until(rto_deadline);
        let idle_timer = sleep_until(idle_deadline);
        let delayed_ack_timer = sleep_until(ack_deadline);
        let mtu_probe_timer = sleep_until(mtu_probe_deadline);

        tokio::pin!(rto_timer);
        tokio::pin!(idle_timer);
        tokio::pin!(delayed_ack_timer);
        tokio::pin!(mtu_probe_timer);

        if self.state.state == ConnectionState::Handshaking {
            if let Err(e) = self.send_initial_packet(None) {
                tracing::warn!("Failed to send initial packet: {:?}", e);
            }
        }

        loop {
            if self.state.state == ConnectionState::Closed {
                break;
            }

            tokio::select! {
                Some(msg) = self.receiver.recv() => {
                    idle_deadline = TokioInstant::now() + Duration::from_secs(60);
                    idle_timer.as_mut().reset(idle_deadline);

                    match msg {
                        ActorMessage::IncomingPacket { data, addr } => {
                            let _ = self.process_incoming_packet(data, addr);
                            if self.pending_acks > 0 {
                                let next_ack = TokioInstant::now() + Duration::from_millis(25);
                                if ack_deadline > next_ack {
                                    ack_deadline = next_ack;
                                    delayed_ack_timer.as_mut().reset(ack_deadline);
                                }
                            }
                        }
                        ActorMessage::OutgoingData { stream_id, data, respond_to } => {
                            self.last_active_stream_id = stream_id;
                            let result = self.process_outgoing_data(stream_id, data);
                            let _ = respond_to.send(result);
                        }
                        ActorMessage::GetMtu { respond_to } => {
                            let _ = respond_to.send(self.state.mtu);
                        }
                        ActorMessage::CloseStream { stream_id } => {
                            if let Err(e) = self.send_stream_close(stream_id) {
                                tracing::warn!("Failed to send StreamClose: {}", e);
                            }
                            self.state.streams.remove(&stream_id);

                            if self.state.streams.is_empty() {
                                let _ = self.initiate_close();
                                idle_deadline = TokioInstant::now() + Duration::from_secs(5);
                                idle_timer.as_mut().reset(idle_deadline);
                            }
                        }
                        ActorMessage::OpenStream { respond_to } => {
                            let stream_id = self.next_stream_id;
                            self.next_stream_id += 1;

                            let (data_tx, data_rx) = mpsc::channel(2048);
                            let window_opened = Arc::new(Notify::new());
                            self.state.streams.insert(stream_id, StreamState::new(data_tx, window_opened.clone()));

                            let stream = ZtStream::new(self.endpoint.clone(), self.scid.clone(), stream_id, data_rx, window_opened);
                            let _ = respond_to.send(Ok(stream));
                        }
                        ActorMessage::Close => {
                            let _ = self.initiate_close();
                            idle_deadline = TokioInstant::now() + Duration::from_secs(5);
                            idle_timer.as_mut().reset(idle_deadline);
                        }
                    }
                }

                _ = &mut delayed_ack_timer => {
                    if self.pending_acks > 0 { let _ = self.flush_acks(); }
                    ack_deadline = TokioInstant::now() + SLEEP_FOREVER;
                    delayed_ack_timer.as_mut().reset(ack_deadline);
                }

                _ = &mut rto_timer => {
                    if self.handle_retransmits().is_err() { break; }
                    let rto = self.state.rtt + self.state.rttvar * 4;
                    rto_deadline = TokioInstant::now() + rto.max(Duration::from_millis(50));
                    rto_timer.as_mut().reset(rto_deadline);
                }

                _ = &mut mtu_probe_timer => {
                    if let Err(e) = self.send_mtu_probe() {
                        tracing::debug!("Failed to send MTU probe: {}", e);
                    }
                    mtu_probe_deadline = TokioInstant::now() + Duration::from_secs(15);
                    mtu_probe_timer.as_mut().reset(mtu_probe_deadline);
                }

                _ = &mut idle_timer => { break; }
            }
        }
        self.routing_table.remove(&self.scid);
    }

    fn check_key_rotation(&mut self, pn: u64, _tx: bool) -> bool {
        let epoch = pn / 16_000_000;
        let key_phase = (epoch % 2) != 0;
        if epoch > self.state.current_key_epoch
            && let Some(crypto) = self.state.crypto.as_mut()
        {
            crypto.rotate_keys();
            self.state.current_key_epoch = epoch;
        }
        key_phase
    }

    fn send_mtu_probe(&mut self) -> Result<()> {
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
        let key_phase = self.check_key_rotation(pn, true);

        let total_buffered = self.state.get_total_buffered_bytes();
        self.state.local_window = (1024u32 * 1024u32).saturating_sub(total_buffered as u32);
        let header = PacketHeader {
            p_type: PacketType::MtuProbe,
            is_long: false,
            version: 0,
            dcid: self.state.dcid.clone(),
            scid: vec![],
            packet_number: pn,
            key_phase,
        };

        let mut packet = BytesMut::with_capacity(target_size + 32);
        header.encode(&mut packet);
        let header_len = packet.len();

        let frame = Frame::Padding(target_size.saturating_sub(header_len + 16));
        frame.encode(&mut packet);
        let payload_len = packet.len() - header_len;
        packet.put_bytes(0, 16); // tag space

        let crypto = self.state.crypto.as_mut().ok_or(ZtError::Unauthorized)?;
        {
            let packet_slice = packet.as_mut();
            let (aad, rest) = packet_slice.split_at_mut(header_len);
            let (payload, tag_space) = rest.split_at_mut(payload_len);
            let tag = crypto.encrypt_in_place(pn, aad, payload)?;
            tag_space.copy_from_slice(&tag);
        }

        let packet_slice = packet.as_mut();
        if let Some(offset) = PacketHeader::get_pn_offset(packet_slice) {
            crypto.apply_header_protection(packet_slice, offset)?;
        }

        if let Err(e) = self.sendmsg_vectored(&[IoSlice::new(packet_slice)]) {
            tracing::debug!("Failed to send MTU probe vector: {}", e);
        }

        self.state.unacked_packets.insert(
            pn,
            UnackedPacket {
                data: packet.freeze(),
                sent_at: StdInstant::now(),
                retries: 0,
                stream_id: 0,
                start_offset: 0,
                end_offset: 0,
                is_mtu_probe: true,
            },
        );
        self.state.mtu_probes.insert(pn, target_size);

        Ok(())
    }

    fn process_incoming_packet(&mut self, data: Bytes, addr: SocketAddr) -> Result<()> {
        self.state.bytes_received += data.len();
        let is_short_header = !data.is_empty() && (data[0] & 0x80) == 0;

        let mut mutable_data = data.to_vec(); // Still need to copy for decryption in place
        let mut use_prev_key = false;

        if is_short_header {
            let key_phase = (data[0] & 0x40) != 0;
            let expected_kp = (self.state.current_key_epoch % 2) != 0;
            if key_phase != expected_kp {
                use_prev_key = true;
            }

            if let Some(crypto) = self.state.crypto.as_ref() {
                if let Some(offset) = PacketHeader::get_pn_offset(&mutable_data) {
                    crypto.remove_header_protection(&mut mutable_data, offset, use_prev_key)?;
                }
            } else {
                return Err(ZtError::Unauthorized);
            }
        } else {
            if let Some(offset) = PacketHeader::get_pn_offset(&mutable_data) {
                if let Some(dcid) = crate::util::extract_dcid_fast(&mutable_data) {
                    let crypto = crate::crypto::CryptoContext::initial(&dcid, true);
                    crypto.remove_header_protection(&mut mutable_data, offset, false)?;
                }
            }
        }

        let mut data_cursor = Bytes::from(mutable_data.clone());
        let initial_len = data_cursor.remaining();
        let header = PacketHeader::decode(&mut data_cursor)?;
        let header_len = initial_len - data_cursor.remaining();
        let aad = &mutable_data[..header_len];
        let mut payload = mutable_data[header_len..].to_vec();

        if self.state.is_replay(header.packet_number) {
            return Ok(());
        }

        let expected_kp = (self.state.current_key_epoch % 2) != 0;
        let highest = self.state.highest_processed_pn.unwrap_or(0);
        if is_short_header && header.key_phase != expected_kp && header.packet_number >= highest {
            if let Some(crypto) = self.state.crypto.as_mut() {
                crypto.rotate_keys();
                self.state.current_key_epoch += 1;
                use_prev_key = false;
            }
        }

        match header.p_type {
            PacketType::Handshake if self.state.state == ConnectionState::Handshaking => {
                self.handle_handshake_response(header, Bytes::from(payload), aad, addr)
            }
            PacketType::Retry if self.state.state == ConnectionState::Handshaking => {
                self.handle_retry_packet(header, Bytes::from(payload), addr)
            }
            PacketType::Data | PacketType::MtuProbe | PacketType::Close
                if self.state.state == ConnectionState::Active =>
            {
                let crypto = self.state.crypto.as_ref().ok_or(ZtError::Unauthorized)?;
                if payload.len() < 16 {
                    return Ok(());
                }
                let tag_idx = payload.len() - 16;
                let tag = payload[tag_idx..].try_into().unwrap();
                let payload_body = &mut payload[..tag_idx];
                crypto.decrypt_in_place(
                    header.packet_number,
                    aad,
                    payload_body,
                    &tag,
                    use_prev_key,
                )?;

                self.state.addr = addr;
                self.state.mark_processed(header.packet_number);

                let mut payload_bytes = Bytes::from(payload_body.to_vec());
                while payload_bytes.remaining() > 0 {
                    if let Ok(frame) = Frame::decode(&mut payload_bytes) {
                        self.handle_frame(frame, header.packet_number)?;
                    } else {
                        break;
                    }
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }

    fn handle_frame(&mut self, frame: Frame, _pn: u64) -> Result<()> {
        match frame {
            Frame::Stream { id, offset, data } => {
                if !self.state.streams.contains_key(&id) {
                    let (data_tx, data_rx) = mpsc::channel(2048);
                    let window_opened = Arc::new(Notify::new());
                    self.state
                        .streams
                        .insert(id, StreamState::new(data_tx, window_opened.clone()));

                    let stream = ZtStream::new(
                        self.endpoint.clone(),
                        self.scid.clone(),
                        id,
                        data_rx,
                        window_opened,
                    );
                    let _ = self.incoming_streams_tx.try_send(stream);

                    self.next_stream_id = self.next_stream_id.max(id + 1);
                }

                let stream = self.state.streams.get_mut(&id).unwrap();
                if offset < stream.expected_rx_offset {
                    self.pending_acks += 1;
                    return Ok(());
                }

                if !data.is_empty() {
                    let end_offset = offset + data.len() as u64;
                    let window_size = stream.window_size;
                    let buf = stream.ensure_buffer();
                    for (i, byte) in data.iter().enumerate() {
                        buf[((offset + i as u64) % window_size) as usize] = *byte;
                    }
                    stream.received_ranges.insert(offset, end_offset);
                    // Merge ranges
                    let mut merged = BTreeMap::new();
                    let mut current: Option<(u64, u64)> = None;
                    for (&s, &e) in &stream.received_ranges {
                        if let Some(ref mut c) = current {
                            if s <= c.1 {
                                c.1 = c.1.max(e);
                            } else {
                                merged.insert(c.0, c.1);
                                current = Some((s, e));
                            }
                        } else {
                            current = Some((s, e));
                        }
                    }
                    if let Some(c) = current {
                        merged.insert(c.0, c.1);
                    }
                    stream.received_ranges = merged;
                    stream.buffered_bytes += data.len();
                }

                while let Some((&s, &e)) = stream.received_ranges.iter().next() {
                    if s <= stream.expected_rx_offset {
                        let avail = (e - stream.expected_rx_offset) as usize;
                        let mut out = vec![0u8; avail];
                        let window_size = stream.window_size;
                        let expected_rx_offset = stream.expected_rx_offset;
                        let buf = stream.ensure_buffer();
                        for (i, byte) in out.iter_mut().enumerate() {
                            *byte = buf[((expected_rx_offset + i as u64) % window_size) as usize];
                        }
                        if stream.app_tx.try_send(Bytes::from(out)).is_ok() {
                            stream.expected_rx_offset = e;
                            stream.buffered_bytes = stream.buffered_bytes.saturating_sub(avail);
                            stream.received_ranges.remove(&s);
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                self.pending_acks += 1;
                if self.pending_acks >= 10 {
                    let _ = self.flush_acks();
                }
            }
            Frame::Ack {
                largest_acked,
                window_size,
                ack_ranges,
            } => {
                self.state
                    .handle_ack(largest_acked, window_size, &ack_ranges);
            }
            Frame::ConnectionClose => {
                self.state.state = ConnectionState::Closed;
            }
            Frame::StreamClose { id } => {
                self.state.streams.remove(&id);
            }
            _ => {}
        }
        Ok(())
    }

    fn flush_acks(&mut self) -> Result<()> {
        if self.pending_acks == 0 {
            return Ok(());
        }
        let pn = self.state.get_next_packet_number()?;
        let kp = self.check_key_rotation(pn, true);
        self.state.local_window =
            (1024u32 * 1024u32).saturating_sub(self.state.get_total_buffered_bytes() as u32);

        let header = PacketHeader {
            p_type: PacketType::Data,
            is_long: false,
            version: 0,
            dcid: self.state.dcid.clone(),
            scid: vec![],
            packet_number: pn,
            key_phase: kp,
        };
        let mut packet = BytesMut::with_capacity(128);
        header.encode(&mut packet);
        let header_len = packet.len();
        let ack_ranges = self.state.get_ack_ranges();
        Frame::Ack {
            largest_acked: self.state.highest_processed_pn.unwrap_or(0),
            window_size: self.state.local_window,
            ack_ranges,
        }
        .encode(&mut packet);
        let payload_len = packet.len() - header_len;
        packet.put_bytes(0, 16);

        let crypto = self.state.crypto.as_mut().ok_or(ZtError::Unauthorized)?;
        {
            let p_slice = packet.as_mut();
            let (aad, rest) = p_slice.split_at_mut(header_len);
            let (payload, tag_space) = rest.split_at_mut(payload_len);
            let tag = crypto.encrypt_in_place(pn, aad, payload)?;
            tag_space.copy_from_slice(&tag);
        }
        if let Some(offset) = PacketHeader::get_pn_offset(packet.as_mut()) {
            crypto.apply_header_protection(packet.as_mut(), offset)?;
        }
        if let Err(e) = self.sendmsg_vectored(&[IoSlice::new(&packet)]) {
            tracing::warn!("Failed to flush acks: {}", e);
        }
        self.pending_acks = 0;
        Ok(())
    }

    fn process_outgoing_data(&mut self, stream_id: u32, data: Bytes) -> Result<()> {
        if self.state.remote_window < data.len() as u32
            || self.state.bytes_in_flight + data.len() > self.state.cwnd
        {
            return Err(ZtError::Io(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "Window or CWND full",
            )));
        }
        let pn = self.state.get_next_packet_number()?;
        let kp = self.check_key_rotation(pn, true);
        let header = PacketHeader {
            p_type: PacketType::Data,
            is_long: false,
            version: 0,
            dcid: self.state.dcid.clone(),
            scid: vec![],
            packet_number: pn,
            key_phase: kp,
        };

        let (start, end) = {
            let stream = self
                .state
                .streams
                .get_mut(&stream_id)
                .ok_or(ZtError::ActorFailed)?;
            let start = stream.next_tx_offset;
            stream.next_tx_offset += data.len() as u64;
            (start, stream.next_tx_offset)
        };

        let mut packet = BytesMut::with_capacity(data.len() + 128);
        header.encode(&mut packet);
        let h_len = packet.len();
        Frame::Stream {
            id: stream_id,
            offset: start,
            data: data.clone(),
        }
        .encode(&mut packet);
        let p_len = packet.len() - h_len;
        packet.put_bytes(0, 16);

        let crypto = self.state.crypto.as_mut().ok_or(ZtError::Unauthorized)?;
        {
            let p_slice = packet.as_mut();
            let (aad, rest) = p_slice.split_at_mut(h_len);
            let (payload, tag_space) = rest.split_at_mut(p_len);
            let tag = crypto.encrypt_in_place(pn, aad, payload)?;
            tag_space.copy_from_slice(&tag);
        }
        if let Some(offset) = PacketHeader::get_pn_offset(packet.as_mut()) {
            crypto.apply_header_protection(packet.as_mut(), offset)?;
        }

        let frozen = packet.freeze();
        let packet_len = frozen.len();
        self.sendmsg_vectored(&[IoSlice::new(&frozen)])?;
        self.state.unacked_packets.insert(
            pn,
            UnackedPacket {
                data: frozen,
                sent_at: StdInstant::now(),
                retries: 0,
                stream_id,
                start_offset: start,
                end_offset: end,
                is_mtu_probe: false,
            },
        );
        self.state.bytes_in_flight += packet_len;
        self.state.remote_window -= data.len() as u32;
        Ok(())
    }

    fn handle_retransmits(&mut self) -> Result<()> {
        let now = StdInstant::now();
        let rto = (self.state.rtt + self.state.rttvar * 4).max(Duration::from_millis(50));
        let mut to_send = Vec::new();
        let mut to_drop = Vec::new();

        for (&pn, up) in self.state.unacked_packets.iter_mut() {
            if now.duration_since(up.sent_at) > rto {
                if up.retries > 10 {
                    to_drop.push(pn);
                } else {
                    up.retries += 1;
                    up.sent_at = now;
                    to_send.push(up.data.clone());
                }
            }
        }

        for pn in &to_drop {
            if let Some(up) = self.state.unacked_packets.remove(pn) {
                self.state.bytes_in_flight =
                    self.state.bytes_in_flight.saturating_sub(up.data.len());
            }
        }
        if !to_send.is_empty() {
            self.state.handle_loss();
            for p in to_send {
                if let Err(e) = self.sendmsg_vectored(&[IoSlice::new(&p)]) {
                    tracing::warn!("Failed to retransmit: {}", e);
                }
            }
        }
        if !self.state.unacked_packets.is_empty()
            && to_drop.len() == self.state.unacked_packets.len()
        {
            return Err(ZtError::Timeout);
        }
        Ok(())
    }

    fn send_stream_close(&mut self, stream_id: u32) -> Result<()> {
        let pn = self.state.get_next_packet_number()?;
        let kp = self.check_key_rotation(pn, true);
        let header = PacketHeader {
            p_type: PacketType::Data,
            is_long: false,
            version: 0,
            dcid: self.state.dcid.clone(),
            scid: vec![],
            packet_number: pn,
            key_phase: kp,
        };
        let mut packet = BytesMut::with_capacity(128);
        header.encode(&mut packet);
        let h_len = packet.len();
        Frame::StreamClose { id: stream_id }.encode(&mut packet);
        let p_len = packet.len() - h_len;
        packet.put_bytes(0, 16);

        let crypto = self.state.crypto.as_mut().ok_or(ZtError::Unauthorized)?;
        {
            let p_slice = packet.as_mut();
            let (aad, rest) = p_slice.split_at_mut(h_len);
            let (payload, tag_space) = rest.split_at_mut(p_len);
            let tag = crypto.encrypt_in_place(pn, aad, payload)?;
            tag_space.copy_from_slice(&tag);
        }

        if let Some(offset) = PacketHeader::get_pn_offset(packet.as_mut()) {
            crypto.apply_header_protection(packet.as_mut(), offset)?;
        }

        let frozen = packet.freeze();
        self.sendmsg_vectored(&[IoSlice::new(&frozen)])?;
        self.state.unacked_packets.insert(
            pn,
            UnackedPacket {
                data: frozen,
                sent_at: StdInstant::now(),
                retries: 0,
                stream_id,
                start_offset: 0,
                end_offset: 0,
                is_mtu_probe: false,
            },
        );
        Ok(())
    }

    fn initiate_close(&mut self) -> Result<()> {
        self.state.state = ConnectionState::Closing;
        let pn = self.state.get_next_packet_number()?;
        let kp = self.check_key_rotation(pn, true);
        let h = PacketHeader {
            p_type: PacketType::Close,
            is_long: false,
            version: 0,
            dcid: self.state.dcid.clone(),
            scid: vec![],
            packet_number: pn,
            key_phase: kp,
        };
        let mut p = BytesMut::with_capacity(64);
        h.encode(&mut p);
        let h_len = p.len();
        Frame::ConnectionClose.encode(&mut p);
        let p_len = p.len() - h_len;
        p.put_bytes(0, 16);
        let crypto = self.state.crypto.as_mut().ok_or(ZtError::Unauthorized)?;
        {
            let slice = p.as_mut();
            let (aad, rest) = slice.split_at_mut(h_len);
            let (payload, tag) = rest.split_at_mut(p_len);
            let t = crypto.encrypt_in_place(pn, aad, payload)?;
            tag.copy_from_slice(&t);
        }
        if let Some(offset) = PacketHeader::get_pn_offset(p.as_mut()) {
            crypto.apply_header_protection(p.as_mut(), offset)?;
        }
        let frozen = p.freeze();
        if let Err(e) = self.sendmsg_vectored(&[IoSlice::new(&frozen)]) {
            tracing::warn!("Failed to send close packet: {}", e);
        }
        self.state.unacked_packets.insert(
            pn,
            UnackedPacket {
                data: frozen,
                sent_at: StdInstant::now(),
                retries: 0,
                stream_id: 0,
                start_offset: 0,
                end_offset: 0,
                is_mtu_probe: false,
            },
        );
        Ok(())
    }

    fn send_initial_packet(&mut self, cookie: Option<Bytes>) -> Result<()> {
        let pn = self.state.get_next_packet_number()?;
        let h = PacketHeader {
            p_type: PacketType::Initial,
            is_long: true,
            version: 1,
            dcid: self.state.dcid.clone(),
            scid: self.state.scid.clone(),
            packet_number: pn,
            key_phase: false,
        };
        let mut p = BytesMut::with_capacity(1200);
        h.encode(&mut p);
        let h_len = p.len();
        Frame::Handshake {
            public_key: *self.public_key.as_bytes(),
            ed_public_key: *self.ed_public_key.as_bytes(),
            signature: self
                .ed_signing_key
                .sign(self.public_key.as_bytes())
                .to_bytes(),
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
            let slice = p.as_mut();
            let (aad, rest) = slice.split_at_mut(h_len);
            let (payload, tag) = rest.split_at_mut(p_len);
            let t = crypto.encrypt_in_place(pn, aad, payload)?;
            tag.copy_from_slice(&t);
        }
        if let Some(offset) = PacketHeader::get_pn_offset(p.as_mut()) {
            crypto.apply_header_protection(p.as_mut(), offset)?;
        }
        if let Err(e) = self.sendmsg_vectored(&[IoSlice::new(p.as_ref())]) {
            tracing::debug!("Initial packet send error: {}", e);
        }
        Ok(())
    }

    fn handle_handshake_response(
        &mut self,
        header: PacketHeader,
        mut payload: Bytes,
        aad: &[u8],
        addr: SocketAddr,
    ) -> Result<()> {
        let crypto = crate::crypto::CryptoContext::initial(&header.dcid, true);
        if payload.len() < 16 {
            return Ok(());
        }
        let tag = payload.split_off(payload.len() - 16);
        let mut payload_mut = payload.to_vec();
        crypto.decrypt_in_place(
            header.packet_number,
            aad,
            &mut payload_mut,
            &tag[..16].try_into().unwrap(),
            false,
        )?;

        let mut payload_bytes = Bytes::from(payload_mut);
        let mut handshake = None;
        while payload_bytes.remaining() > 0 {
            if let Ok(Frame::Handshake {
                public_key,
                ed_public_key,
                signature,
            }) = Frame::decode(&mut payload_bytes)
            {
                handshake = Some((public_key, ed_public_key, signature));
            }
        }
        let Some((pk_bytes, remote_ed_pk_bytes, remote_sig_bytes)) = handshake else {
            return Err(ZtError::Crypto("No handshake".into()));
        };
        let remote_ed_pk = VerifyingKey::from_bytes(&remote_ed_pk_bytes)
            .map_err(|_| ZtError::Crypto("Invalid EdPK".into()))?;
        remote_ed_pk
            .verify(&pk_bytes, &Signature::from_bytes(&remote_sig_bytes))
            .map_err(|_| ZtError::Crypto("Invalid Sig".into()))?;

        let shared = crate::crypto::CryptoContext::compute_shared_secret(
            &self.static_secret,
            PublicKey::from(pk_bytes),
        );
        self.state.dcid = header.scid.clone();
        self.state.crypto = Some(crate::crypto::CryptoContext::from_shared_secret(
            shared,
            &self.state.scid,
            &self.state.dcid,
            self.psk,
            true,
        ));
        self.state.addr = addr;
        self.state.state = ConnectionState::Active;
        self.state.mark_processed(header.packet_number);
        if let Some(tx) = self.handshake_waiter.take() {
            let _ = tx.send(());
        }
        Ok(())
    }

    fn handle_retry_packet(
        &mut self,
        _header: PacketHeader,
        payload: Bytes,
        _addr: SocketAddr,
    ) -> Result<()> {
        self.send_initial_packet(Some(payload))
    }
}
