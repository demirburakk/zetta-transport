use crate::transport::state::{ConnectionState, ZtConnection};
use crate::error::{Result, ZtError};
use crate::protocol::packet::{PacketHeader, PacketType};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use std::time::Duration;
use tokio::time::{sleep_until, Instant};
use dashmap::DashMap;
use x25519_dalek::{PublicKey, StaticSecret};

pub enum ActorMessage {
    IncomingPacket { data: Bytes, addr: SocketAddr },
    OutgoingData { stream_id: u32, data: Bytes, respond_to: oneshot::Sender<Result<()>> },
    Close,
}

pub struct ZtConnectionActor {
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) receiver: mpsc::Receiver<ActorMessage>,
    pub(crate) state: ZtConnection,
    pub(crate) pending_acks: u32,
    pub(crate) public_key: PublicKey,
    pub(crate) static_secret: StaticSecret,
    pub(crate) psk: Option<[u8; 32]>,
    pub(crate) handshake_waiter: Option<oneshot::Sender<()>>,
    pub(crate) routing_table: Arc<DashMap<Vec<u8>, mpsc::Sender<ActorMessage>>>,
    pub(crate) scid: Vec<u8>,
    pub(crate) last_active_stream_id: u32,
}

const SLEEP_FOREVER: Duration = Duration::from_secs(86400 * 365);

impl ZtConnectionActor {
    pub async fn run(mut self) {
        let mut rto_deadline = Instant::now() + self.state.rtt;
        let mut idle_deadline = Instant::now() + Duration::from_secs(60);
        let mut ack_deadline = Instant::now() + SLEEP_FOREVER;
        let mut keep_alive_deadline = Instant::now() + Duration::from_secs(20);

        let rto_timer = sleep_until(rto_deadline);
        let idle_timer = sleep_until(idle_deadline);
        let delayed_ack_timer = sleep_until(ack_deadline);
        let keep_alive_timer = sleep_until(keep_alive_deadline);

        tokio::pin!(rto_timer);
        tokio::pin!(idle_timer);
        tokio::pin!(delayed_ack_timer);
        tokio::pin!(keep_alive_timer);

        tracing::info!("Actor spawned for CID: {:?}", self.state.dcid);

        if self.state.state == ConnectionState::Handshaking {
            let _ = self.send_initial_packet();
        }

        loop {
            if self.state.state == ConnectionState::Closed {
                break;
            }

            tokio::select! {
                Some(msg) = self.receiver.recv() => {
                    idle_deadline = Instant::now() + Duration::from_secs(60);
                    idle_timer.as_mut().reset(idle_deadline);

                    match msg {
                        ActorMessage::IncomingPacket { data, addr } => {
                            let _ = self.process_incoming_packet(data, addr);
                            if self.pending_acks > 0 {
                                let next_ack = Instant::now() + Duration::from_millis(25);
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
                            
                            keep_alive_deadline = Instant::now() + Duration::from_secs(20);
                            keep_alive_timer.as_mut().reset(keep_alive_deadline);
                        }
                        ActorMessage::Close => {
                            let _ = self.initiate_close();
                            idle_deadline = Instant::now() + Duration::from_secs(5);
                            idle_timer.as_mut().reset(idle_deadline);
                        }
                    }
                }

                _ = &mut delayed_ack_timer => {
                    if self.pending_acks > 0 {
                        let _ = self.flush_acks();
                    }
                    ack_deadline = Instant::now() + SLEEP_FOREVER;
                    delayed_ack_timer.as_mut().reset(ack_deadline);
                }

                _ = &mut rto_timer => {
                    self.handle_retransmits();
                    rto_deadline = Instant::now() + self.state.rtt.saturating_mul(4).max(Duration::from_millis(50));
                    rto_timer.as_mut().reset(rto_deadline);
                }

                _ = &mut keep_alive_timer => {
                    let _ = self.send_keep_alive();
                    keep_alive_deadline = Instant::now() + Duration::from_secs(20);
                    keep_alive_timer.as_mut().reset(keep_alive_deadline);
                }

                _ = &mut idle_timer => {
                    tracing::warn!("Idle timeout reached for CID: {:?}. Terminating.", self.state.dcid);
                    break;
                }
            }
        }
        
        self.routing_table.remove(&self.scid);
        tracing::info!("Actor for CID {:?} terminated and cleaned up.", self.scid);
    }

    fn check_key_rotation(&mut self, pn: u64) {
        let epoch = pn / 16_000_000;
        if epoch > self.state.current_key_epoch {
            if let Some(crypto) = self.state.crypto.as_mut() {
                crypto.rotate_keys();
                self.state.current_key_epoch = epoch;
                tracing::info!("Keys rotated successfully for epoch {}", epoch);
            }
        }
    }

    fn send_keep_alive(&mut self) -> Result<()> {
        if self.state.state != ConnectionState::Active { return Ok(()); }
        let pn = self.state.get_next_packet_number()?;
        self.check_key_rotation(pn);
        
        let total_buffered = self.state.get_total_buffered_bytes();
        self.state.local_window = (1024u32 * 1024u32).saturating_sub(total_buffered as u32);
        let header = PacketHeader {
            p_type: PacketType::MtuProbe,
            is_long: false,
            version: 0,
            dcid: self.state.dcid.clone(),
            scid: vec![],
            packet_number: pn,
            window_size: self.state.local_window,
            stream_id: 0,
            offset: 0,
            acked_pn: 0,
        };

        let target_size = if self.state.mtu < 1450 { 1450 } else { 64 };
        self.state.mtu_probes.insert(pn, target_size);

        let mut buf = BytesMut::with_capacity(target_size);
        header.encode(&mut buf);
        let header_bytes = buf.freeze();
        
        let payload_len = target_size.saturating_sub(header_bytes.len() + 16);
        let mut payload = vec![0u8; payload_len];

        let crypto = self.state.crypto.as_mut().ok_or(ZtError::Unauthorized)?;
        let tag = crypto.encrypt_in_place(pn, &header_bytes, &mut payload)?;

        let mut full_packet = BytesMut::from(&header_bytes[..]);
        full_packet.extend_from_slice(&payload);
        full_packet.extend_from_slice(&tag);

        let _ = self.socket.try_send_to(&full_packet.freeze(), self.state.addr);
        Ok(())
    }

    fn process_incoming_packet(&mut self, original_data: Bytes, addr: SocketAddr) -> Result<()> {
        let mut data_cursor = original_data.clone();
        let initial_len = data_cursor.remaining();
        let header = PacketHeader::decode(&mut data_cursor)?;
        let header_len = initial_len - data_cursor.remaining();
        let aad = &original_data[..header_len];
        let payload = data_cursor; 

        if self.state.is_replay(header.packet_number) {
            return Err(ZtError::InvalidPacket("Replay attack or duplicate".into()));
        }

        self.check_key_rotation(header.packet_number);

        match header.p_type {
            PacketType::Handshake if self.state.state == ConnectionState::Handshaking => {
                self.handle_handshake_response(header, payload, aad, addr)
            }
            PacketType::Retry if self.state.state == ConnectionState::Handshaking => {
                self.handle_retry_packet(header, payload, addr)
            }
            PacketType::Data if self.state.state == ConnectionState::Active => {
                self.handle_data_packet(header, payload, aad, addr)
            }
            PacketType::Ack => {
                self.handle_ack_packet(header, payload, aad, addr)
            }
            PacketType::MtuProbe if self.state.state == ConnectionState::Active => {
                self.handle_mtu_probe(header, payload, aad, addr)
            }
            PacketType::Close => {
                self.handle_close_packet(header, payload, aad, addr)
            }
            _ => Ok(()),
        }
    }

    fn handle_data_packet(&mut self, header: PacketHeader, mut payload: Bytes, aad: &[u8], addr: SocketAddr) -> Result<()> {
        let crypto = self.state.crypto.as_ref().ok_or(ZtError::Unauthorized)?;
        if payload.len() < 16 { return Err(ZtError::InvalidPacket("Too short for tag".into())); }
        let tag_bytes = payload.split_off(payload.len() - 16);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&tag_bytes);
        let mut payload_mut = payload.to_vec();
        crypto.decrypt_in_place(header.packet_number, aad, &mut payload_mut, &tag)?;
        
        self.state.addr = addr;
        self.state.mark_processed(header.packet_number);
        self.last_active_stream_id = header.stream_id;

        self.state.local_window = (1024u32 * 1024u32).saturating_sub(self.state.get_total_buffered_bytes() as u32);

        if !self.state.streams.contains_key(&header.stream_id) {
            return Ok(());
        }

        let stream = self.state.streams.get_mut(&header.stream_id).unwrap();

        if header.offset < stream.expected_rx_offset {
            self.pending_acks += 1;
            return Ok(());
        }

        if !payload_mut.is_empty() {
            if stream.reorder_buffer.len() > 1024 {
                return Err(ZtError::InvalidPacket("Reorder buffer full. Dropping.".into()));
            }
            stream.buffered_bytes += payload_mut.len();
            stream.reorder_buffer.insert(header.offset, Bytes::from(payload_mut));
        }

        loop {
            if let Some(data) = stream.reorder_buffer.remove(&stream.expected_rx_offset) {
                let data_len = data.len();
                match stream.app_tx.try_send(data) {
                    Ok(_) => {
                        stream.expected_rx_offset += data_len as u64;
                        stream.buffered_bytes = stream.buffered_bytes.saturating_sub(data_len);
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Full(returned_data)) => {
                        stream.reorder_buffer.insert(stream.expected_rx_offset, returned_data);
                        break; 
                    }
                    Err(_) => break, 
                }
            } else {
                break;
            }
        }

        self.pending_acks += 1;
        if self.pending_acks >= 10 {
            let _ = self.flush_acks();
        }

        Ok(())
    }

    fn handle_ack_packet(&mut self, header: PacketHeader, mut payload: Bytes, aad: &[u8], addr: SocketAddr) -> Result<()> {
        let crypto = self.state.crypto.as_ref().ok_or(ZtError::Unauthorized)?;
        if payload.len() < 16 { return Err(ZtError::InvalidPacket("Too short for tag".into())); }
        let tag_bytes = payload.split_off(payload.len() - 16);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&tag_bytes);
        let mut payload_mut = payload.to_vec();
        crypto.decrypt_in_place(header.packet_number, aad, &mut payload_mut, &tag)?;
        
        self.state.addr = addr;
        
        self.state.handle_ack(header.acked_pn, header.stream_id, header.offset, header.window_size);

        if let Some(stream) = self.state.streams.get(&header.stream_id) {
            if stream.dup_ack_count == 3 {
                let expected_offset = stream.last_acked_offset;
                let mut to_retransmit = None;
                for (_pn, (packet, sent_time, retries, sid, start_offset, _end_offset)) in self.state.unacked_packets.iter_mut() {
                    if *sid == header.stream_id && *start_offset == expected_offset {
                        *sent_time = std::time::Instant::now();
                        *retries += 1;
                        to_retransmit = Some(packet.clone());
                        break;
                    }
                }
                if let Some(packet) = to_retransmit {
                    tracing::debug!("Fast Retransmit triggered for stream {} offset {}", header.stream_id, expected_offset);
                    let _ = self.socket.try_send_to(&packet, self.state.addr);
                    self.state.handle_loss();
                }
            }
        }

        Ok(())
    }

    fn handle_mtu_probe(&mut self, header: PacketHeader, mut payload: Bytes, aad: &[u8], addr: SocketAddr) -> Result<()> {
        let crypto = self.state.crypto.as_ref().ok_or(ZtError::Unauthorized)?;
        if payload.len() < 16 { return Err(ZtError::InvalidPacket("Too short for tag".into())); }
        let tag_bytes = payload.split_off(payload.len() - 16);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&tag_bytes);
        let mut payload_mut = payload.to_vec();
        crypto.decrypt_in_place(header.packet_number, aad, &mut payload_mut, &tag)?;
        
        self.state.addr = addr;
        self.state.mark_processed(header.packet_number);
        self.pending_acks += 1;
        let _ = self.flush_acks();
        Ok(())
    }

    fn handle_close_packet(&mut self, header: PacketHeader, mut payload: Bytes, aad: &[u8], addr: SocketAddr) -> Result<()> {
        if let Some(crypto) = self.state.crypto.as_ref() {
            if payload.len() >= 16 {
                let tag_bytes = payload.split_off(payload.len() - 16);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&tag_bytes);
                let mut payload_mut = payload.to_vec();
                if crypto.decrypt_in_place(header.packet_number, aad, &mut payload_mut, &tag).is_ok() {
                    self.state.addr = addr;
                    self.state.mark_processed(header.packet_number);
                    
                    if self.state.state == ConnectionState::Closing {
                        self.state.state = ConnectionState::Closed;
                    } else {
                        let _ = self.initiate_close();
                        self.state.state = ConnectionState::Closed;
                    }
                }
            }
        }
        Ok(())
    }

    fn flush_acks(&mut self) -> Result<()> {
        if self.pending_acks == 0 { return Ok(()); }
        
        let ack_pn = self.state.get_next_packet_number()?; 
        self.check_key_rotation(ack_pn);

        self.state.local_window = (1024u32 * 1024u32).saturating_sub(self.state.get_total_buffered_bytes() as u32);

        let stream_id = self.last_active_stream_id;
        let offset = self.state.streams.get(&stream_id).map(|s| s.expected_rx_offset).unwrap_or(0);

        let header = PacketHeader {
            p_type: PacketType::Ack,
            is_long: false,
            version: 0,
            dcid: self.state.dcid.clone(),
            scid: vec![],
            packet_number: ack_pn,
            window_size: self.state.local_window,
            stream_id,
            offset,
            acked_pn: self.state.highest_processed_pn, 
        };

        let mut buf = BytesMut::with_capacity(64);
        header.encode(&mut buf);
        let header_bytes = buf.freeze();
        
        let mut payload = vec![]; 
        let crypto = self.state.crypto.as_ref().ok_or(ZtError::Unauthorized)?;
        let tag = crypto.encrypt_in_place(ack_pn, &header_bytes, &mut payload)?;

        let mut full_packet = BytesMut::from(&header_bytes[..]);
        full_packet.extend_from_slice(&tag);

        let _ = self.socket.try_send_to(&full_packet.freeze(), self.state.addr);
        self.pending_acks = 0;
        Ok(())
    }

    fn process_outgoing_data(&mut self, stream_id: u32, data: Bytes) -> Result<()> {
        if self.state.remote_window < data.len() as u32 {
            return Err(ZtError::Io(std::io::Error::new(std::io::ErrorKind::WouldBlock, "Remote window exhausted")));
        }
        if self.state.bytes_in_flight + data.len() > self.state.cwnd {
            return Err(ZtError::Io(std::io::Error::new(std::io::ErrorKind::WouldBlock, "CWND exhausted")));
        }

        let stream = self.state.streams.get_mut(&stream_id).ok_or(ZtError::Unknown)?;
        let start_offset = stream.next_tx_offset;
        stream.next_tx_offset += data.len() as u64;
        let end_offset = stream.next_tx_offset;

        let pn = self.state.get_next_packet_number()?;
        self.check_key_rotation(pn);
        
        let header = PacketHeader {
            p_type: PacketType::Data,
            is_long: false,
            version: 0,
            dcid: self.state.dcid.clone(),
            scid: vec![],
            packet_number: pn,
            window_size: self.state.local_window,
            stream_id,
            offset: start_offset,
            acked_pn: 0,
        };

        let mut buf = BytesMut::with_capacity(64);
        header.encode(&mut buf);
        let header_bytes = buf.freeze();

        let mut payload = data.to_vec();
        let crypto = self.state.crypto.as_ref().ok_or(ZtError::Unauthorized)?;
        let tag = crypto.encrypt_in_place(pn, &header_bytes, &mut payload)?;

        let mut full_packet = BytesMut::from(&header_bytes[..]);
        full_packet.extend_from_slice(&payload);
        full_packet.extend_from_slice(&tag);
        let frozen_packet = full_packet.freeze();

        let _ = self.socket.try_send_to(&frozen_packet, self.state.addr);

        self.state.unacked_packets.insert(pn, (frozen_packet, std::time::Instant::now(), 0, stream_id, start_offset, end_offset));
        self.state.bytes_in_flight += data.len();
        self.state.remote_window -= data.len() as u32;

        Ok(())
    }

    fn handle_retransmits(&mut self) {
        let now = std::time::Instant::now();
        let mut to_send = Vec::new();
        let mut to_remove = Vec::new();
        let mut loss_occurred = false;

        let rto = self.state.rtt.saturating_mul(4).max(Duration::from_millis(50));

        for (pn, (packet, sent_time, retries, _, _, _)) in self.state.unacked_packets.iter_mut() {
            if now.duration_since(*sent_time) > rto {
                loss_occurred = true;
                if *retries > 10 {
                    to_remove.push(*pn);
                } else {
                    *sent_time = now;
                    *retries += 1;
                    to_send.push(packet.clone());
                }
            }
        }

        if loss_occurred {
            self.state.handle_loss();
        }

        for pn in to_remove {
            if let Some((packet, _, _, _, _, _)) = self.state.unacked_packets.remove(&pn) {
                self.state.bytes_in_flight = self.state.bytes_in_flight.saturating_sub(packet.len());
            }
        }

        for packet in to_send {
            let _ = self.socket.try_send_to(&packet, self.state.addr);
        }
    }

    fn initiate_close(&mut self) -> Result<()> {
        self.state.state = ConnectionState::Closing;
        let pn = self.state.get_next_packet_number()?;
        self.check_key_rotation(pn);

        let header = PacketHeader {
            p_type: PacketType::Close,
            is_long: false,
            version: 0,
            dcid: self.state.dcid.clone(),
            scid: vec![],
            packet_number: pn,
            window_size: self.state.local_window,
            stream_id: 0,
            offset: 0,
            acked_pn: 0,
        };
        let mut buf = BytesMut::with_capacity(64);
        header.encode(&mut buf);
        let header_bytes = buf.freeze();

        let mut payload = vec![];
        let crypto = self.state.crypto.as_ref().ok_or(ZtError::Unauthorized)?;
        let tag = crypto.encrypt_in_place(pn, &header_bytes, &mut payload)?;

        let mut full_packet = BytesMut::from(&header_bytes[..]);
        full_packet.extend_from_slice(&tag);
        let frozen = full_packet.freeze();

        let _ = self.socket.try_send_to(&frozen, self.state.addr);
        
        self.state.unacked_packets.insert(pn, (frozen, std::time::Instant::now(), 0, 0, u64::MAX, u64::MAX));
        Ok(())
    }

    fn send_initial_packet(&mut self) -> Result<()> {
        let pn = self.state.get_next_packet_number()?;
        let header = PacketHeader {
            p_type: PacketType::Initial,
            is_long: true,
            version: 1,
            dcid: self.state.dcid.clone(),
            scid: self.state.scid.clone(),
            packet_number: pn,
            window_size: self.state.local_window,
            stream_id: 0,
            offset: 0,
            acked_pn: 0,
        };

        // Enforce 1200 padding for initial
        let mut buf = BytesMut::with_capacity(1200);
        header.encode(&mut buf);
        buf.extend_from_slice(self.public_key.as_bytes());

        while buf.len() < 1200 {
            buf.put_u8(0);
        }

        let _ = self.socket.try_send_to(&buf, self.state.addr);
        Ok(())
    }

    fn handle_handshake_response(&mut self, header: PacketHeader, payload: Bytes, _aad: &[u8], addr: SocketAddr) -> Result<()> {
        if payload.len() < 32 { return Ok(()); }
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&payload[..32]);

        let shared = crate::crypto::CryptoContext::compute_shared_secret(
            self.static_secret.clone(),
            PublicKey::from(pk_bytes),
        );
        self.state.dcid = header.scid.clone();
        self.state.crypto = Some(crate::crypto::CryptoContext::from_shared_secret(
            shared, &self.state.scid, &self.state.dcid, self.psk,
        ));
        self.state.addr = addr;
        self.state.state = ConnectionState::Active;

        self.state.mark_processed(header.packet_number);
        
        if let Some(tx) = self.handshake_waiter.take() { let _ = tx.send(()); }
        Ok(())
    }
    
    fn handle_retry_packet(&mut self, header: PacketHeader, payload: Bytes, _addr: SocketAddr) -> Result<()> {
        let pn = self.state.get_next_packet_number()?;
        let init_header = PacketHeader {
            p_type: PacketType::Initial,
            is_long: true,
            version: 1,
            dcid: header.scid.clone(),
            scid: self.state.scid.clone(),
            packet_number: pn,
            window_size: self.state.local_window,
            stream_id: 0,
            offset: 0,
            acked_pn: 0,
        };

        let mut buf = BytesMut::with_capacity(1200);
        init_header.encode(&mut buf);
        buf.extend_from_slice(self.public_key.as_bytes());
        buf.extend_from_slice(&payload); 

        while buf.len() < 1200 {
            buf.put_u8(0);
        }

        let _ = self.socket.try_send_to(&buf, self.state.addr);
        Ok(())
    }
}
