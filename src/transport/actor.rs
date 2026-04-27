use crate::transport::state::{ConnectionState, ZtConnection};
use crate::error::{Result, ZtError};
use crate::protocol::packet::{PacketHeader, PacketType};
use bytes::{Buf, Bytes, BytesMut};
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
    OutgoingData { data: Bytes, respond_to: oneshot::Sender<Result<()>> },
    Close,
}

pub struct ZtConnectionActor {
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) receiver: mpsc::Receiver<ActorMessage>,
    pub(crate) state: ZtConnection,
    pub(crate) app_tx: mpsc::Sender<Bytes>,
    pub(crate) pending_acks: u32,
    pub(crate) public_key: PublicKey,
    pub(crate) static_secret: StaticSecret,
    pub(crate) psk: Option<[u8; 32]>,
    pub(crate) handshake_waiter: Option<oneshot::Sender<()>>,
    pub(crate) routing_table: Arc<DashMap<Vec<u8>, mpsc::Sender<ActorMessage>>>,
    pub(crate) scid: Vec<u8>,
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
                    // Bağlantı kopmaması için boşta kalma süresini resetle
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
                        ActorMessage::OutgoingData { data, respond_to } => {
                            let result = self.process_outgoing_data(data);
                            let _ = respond_to.send(result);
                            
                            // ÇÖZÜM: Keep-alive timer'ı sıfırla, çünkü veri yolladık
                            keep_alive_deadline = Instant::now() + Duration::from_secs(20);
                            keep_alive_timer.as_mut().reset(keep_alive_deadline);
                        }
                        ActorMessage::Close => {
                            let _ = self.initiate_close();
                            // ÇÖZÜM: TIME_WAIT durumu. 5 saniye bekle, sonra zorla kapat
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
                    // ÇÖZÜM: Sessiz Ölüme Karşı Keep-Alive Yollayıcısı
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

    fn send_keep_alive(&mut self) -> Result<()> {
        if self.state.state != ConnectionState::Active { return Ok(()); }
        let pn = self.state.get_next_packet_number()?;
        
        self.state.local_window = (1024u32 * 1024u32).saturating_sub(self.state.buffered_bytes as u32);
        let header = PacketHeader {
            p_type: PacketType::MtuProbe, // Ping olarak kullanıyoruz
            is_long: false,
            version: 0,
            dcid: self.state.dcid.clone(),
            scid: vec![],
            packet_number: pn,
            window_size: self.state.local_window,
            stream_id: 0,
            offset: 0,
        };

        let mut buf = BytesMut::with_capacity(64);
        header.encode(&mut buf);
        let header_bytes = buf.freeze();
        
        let payload: &[u8] = &[]; 
        let crypto = self.state.crypto.as_ref().ok_or(ZtError::Unauthorized)?;
        let encrypted = crypto.encrypt(pn, payload, &header_bytes)?;

        let mut full_packet = BytesMut::from(&header_bytes[..]);
        full_packet.extend_from_slice(&encrypted);

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

    fn handle_data_packet(&mut self, header: PacketHeader, payload: Bytes, aad: &[u8], addr: SocketAddr) -> Result<()> {
        let crypto = self.state.crypto.as_ref().ok_or(ZtError::Unauthorized)?;
        let decrypted = crypto.decrypt(header.packet_number, &payload, aad)?;
        
        self.state.addr = addr;
        self.state.mark_processed(header.packet_number);

        self.state.local_window = (1024u32 * 1024u32).saturating_sub(self.state.buffered_bytes as u32);

        if header.offset < self.state.expected_rx_offset {
            self.pending_acks += 1;
            return Ok(());
        }

        if !decrypted.is_empty() {
            if self.state.reorder_buffer.len() > 1024 {
                return Err(ZtError::InvalidPacket("Reorder buffer full. Dropping.".into()));
            }
            self.state.buffered_bytes += decrypted.len();
            self.state.reorder_buffer.insert(header.offset, Bytes::from(decrypted));
        }

        loop {
            if let Some(data) = self.state.reorder_buffer.remove(&self.state.expected_rx_offset) {
                let data_len = data.len();
                match self.app_tx.try_send(data) {
                    Ok(_) => {
                        self.state.expected_rx_offset += data_len as u64;
                        self.state.buffered_bytes = self.state.buffered_bytes.saturating_sub(data_len);
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Full(returned_data)) => {
                        self.state.reorder_buffer.insert(self.state.expected_rx_offset, returned_data);
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

    fn handle_ack_packet(&mut self, header: PacketHeader, payload: Bytes, aad: &[u8], addr: SocketAddr) -> Result<()> {
        let crypto = self.state.crypto.as_ref().ok_or(ZtError::Unauthorized)?;
        let _ = crypto.decrypt(header.packet_number, &payload, aad)?;
        self.state.addr = addr;
        
        self.state.handle_ack(header.offset, header.window_size);

        // ÇÖZÜM: Fast Retransmit (3 Duplicate ACKs)
        if self.state.dup_ack_count == 3 {
            let expected_offset = self.state.last_acked_offset;
            let mut to_retransmit = None;
            for (_pn, (packet, sent_time, retries, start_offset, _end_offset)) in self.state.unacked_packets.iter_mut() {
                if *start_offset == expected_offset {
                    *sent_time = std::time::Instant::now();
                    *retries += 1;
                    to_retransmit = Some(packet.clone());
                    break;
                }
            }
            if let Some(packet) = to_retransmit {
                tracing::debug!("Fast Retransmit triggered for offset: {}", expected_offset);
                let _ = self.socket.try_send_to(&packet, self.state.addr);
                self.state.handle_loss();
            }
        }

        Ok(())
    }

    fn handle_mtu_probe(&mut self, header: PacketHeader, payload: Bytes, aad: &[u8], addr: SocketAddr) -> Result<()> {
        let crypto = self.state.crypto.as_ref().ok_or(ZtError::Unauthorized)?;
        let _ = crypto.decrypt(header.packet_number, &payload, aad)?;
        self.state.addr = addr;
        self.state.mark_processed(header.packet_number);
        self.pending_acks += 1;
        let _ = self.flush_acks();
        Ok(())
    }

    fn handle_close_packet(&mut self, header: PacketHeader, payload: Bytes, aad: &[u8], addr: SocketAddr) -> Result<()> {
        if let Some(crypto) = self.state.crypto.as_ref() {
            if crypto.decrypt(header.packet_number, &payload, aad).is_ok() {
                self.state.addr = addr;
                self.state.mark_processed(header.packet_number);
                
                if self.state.state == ConnectionState::Closing {
                    // ÇÖZÜM: Teardown onayı. Biz kapatıyorduk, karşıdan onay geldi.
                    self.state.state = ConnectionState::Closed;
                } else {
                    // Karşı taraf kapatıyor. CloseAck niyetine Close at ve kapan.
                    let _ = self.initiate_close();
                    self.state.state = ConnectionState::Closed;
                }
            }
        }
        Ok(())
    }

    fn flush_acks(&mut self) -> Result<()> {
        if self.pending_acks == 0 { return Ok(()); }
        
        let ack_pn = self.state.get_next_packet_number()?; 
        self.state.local_window = (1024u32 * 1024u32).saturating_sub(self.state.buffered_bytes as u32);

        let header = PacketHeader {
            p_type: PacketType::Ack,
            is_long: false,
            version: 0,
            dcid: self.state.dcid.clone(),
            scid: vec![],
            packet_number: ack_pn,
            window_size: self.state.local_window,
            stream_id: 0,
            offset: self.state.expected_rx_offset, // ÇÖZÜM: Offset tabanlı ACK ile Fast Retransmit mümkün
        };

        let mut buf = BytesMut::with_capacity(64);
        header.encode(&mut buf);
        let header_bytes = buf.freeze();
        
        let payload: &[u8] = &[]; 
        let crypto = self.state.crypto.as_ref().ok_or(ZtError::Unauthorized)?;
        let encrypted = crypto.encrypt(ack_pn, payload, &header_bytes)?;

        let mut full_packet = BytesMut::from(&header_bytes[..]);
        full_packet.extend_from_slice(&encrypted);

        let _ = self.socket.try_send_to(&full_packet.freeze(), self.state.addr);
        self.pending_acks = 0;
        Ok(())
    }

    fn process_outgoing_data(&mut self, data: Bytes) -> Result<()> {
        if self.state.remote_window < data.len() as u32 {
            return Err(ZtError::Io(std::io::Error::new(std::io::ErrorKind::WouldBlock, "Remote window exhausted")));
        }
        if self.state.bytes_in_flight + data.len() > self.state.cwnd {
            return Err(ZtError::Io(std::io::Error::new(std::io::ErrorKind::WouldBlock, "CWND exhausted")));
        }

        let pn = self.state.get_next_packet_number()?;
        let start_offset = self.state.next_tx_offset;
        
        let header = PacketHeader {
            p_type: PacketType::Data,
            is_long: false,
            version: 0,
            dcid: self.state.dcid.clone(),
            scid: vec![],
            packet_number: pn,
            window_size: self.state.local_window,
            stream_id: 0,
            offset: start_offset,
        };
        self.state.next_tx_offset += data.len() as u64;
        let end_offset = self.state.next_tx_offset;

        let mut buf = BytesMut::with_capacity(64);
        header.encode(&mut buf);
        let header_bytes = buf.freeze();

        let crypto = self.state.crypto.as_ref().ok_or(ZtError::Unauthorized)?;
        let encrypted = crypto.encrypt(pn, &data, &header_bytes)?;

        let mut full_packet = BytesMut::from(&header_bytes[..]);
        full_packet.extend_from_slice(&encrypted);
        let frozen_packet = full_packet.freeze();

        let _ = self.socket.try_send_to(&frozen_packet, self.state.addr);

        self.state.unacked_packets.insert(pn, (frozen_packet, std::time::Instant::now(), 0, start_offset, end_offset));
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

        for (pn, (packet, sent_time, retries, _, _)) in self.state.unacked_packets.iter_mut() {
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
            if let Some((packet, _, _, _, _)) = self.state.unacked_packets.remove(&pn) {
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
        };
        let mut buf = BytesMut::with_capacity(64);
        header.encode(&mut buf);
        let header_bytes = buf.freeze();

        let payload: &[u8] = &[];
        let crypto = self.state.crypto.as_ref().ok_or(ZtError::Unauthorized)?;
        let encrypted = crypto.encrypt(pn, payload, &header_bytes)?;

        let mut full_packet = BytesMut::from(&header_bytes[..]);
        full_packet.extend_from_slice(&encrypted);
        let frozen = full_packet.freeze();

        let _ = self.socket.try_send_to(&frozen, self.state.addr);
        
        // Yeniden iletim için unacked olarak kuyruğa at
        self.state.unacked_packets.insert(pn, (frozen, std::time::Instant::now(), 0, u64::MAX, u64::MAX));
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
        };

        let mut buf = BytesMut::with_capacity(128);
        header.encode(&mut buf);
        buf.extend_from_slice(self.public_key.as_bytes());

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
        };

        let mut buf = BytesMut::with_capacity(128);
        init_header.encode(&mut buf);
        buf.extend_from_slice(self.public_key.as_bytes());
        buf.extend_from_slice(&payload); 

        let _ = self.socket.try_send_to(&buf, self.state.addr);
        Ok(())
    }
}