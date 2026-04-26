use crate::connection::{ConnectionState, ZtConnection};
use crate::crypto::CryptoContext;
use crate::error::{Result, ZtError};
use crate::fec::FecEngine;
use crate::packet::{MAX_PACKET_SIZE, PacketHeader, PacketType};
use bytes::{Buf, Bytes, BytesMut};
use rand::Rng;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;
use x25519_dalek::{PublicKey, StaticSecret};

const RECV_BUFFER_SIZE: usize = 2048;
const BUFFER_CLEANUP_TIMEOUT: Duration = Duration::from_secs(60);
const SESSION_EXPIRY_TIMEOUT: Duration = Duration::from_secs(3600);
const PRUNING_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub struct ReceivedData {
    pub cid: Vec<u8>,
    pub data: Bytes,
}

pub struct ZtEndpoint {
    socket: Arc<UdpSocket>,
    connections: Arc<Mutex<HashMap<Vec<u8>, ZtConnection>>>,
    chaos_mode: Arc<AtomicBool>,
    static_secret: StaticSecret,
    pub public_key: PublicKey,
    pub psk: Option<[u8; 32]>,
    app_rx: Mutex<mpsc::Receiver<ReceivedData>>,
    app_tx: mpsc::Sender<ReceivedData>,
    shutdown_token: CancellationToken,
}

impl ZtEndpoint {
    pub async fn bind(addr: &str, psk: Option<[u8; 32]>) -> Result<Arc<Self>> {
        let (secret, public) = CryptoContext::generate_keypair();
        let socket = UdpSocket::bind(addr).await?;
        let (tx, rx) = mpsc::channel(RECV_BUFFER_SIZE);
        let shutdown_token = CancellationToken::new();

        let endpoint = Arc::new(Self {
            socket: Arc::new(socket),
            connections: Arc::new(Mutex::new(HashMap::new())),
            chaos_mode: Arc::new(AtomicBool::new(false)),
            static_secret: secret,
            public_key: public,
            psk,
            app_rx: Mutex::new(rx),
            app_tx: tx,
            shutdown_token: shutdown_token.clone(),
        });

        // 1. Background Listener Task
        let endpoint_clone = endpoint.clone();
        let token_1 = shutdown_token.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; MAX_PACKET_SIZE];
            loop {
                tokio::select! {
                    _ = token_1.cancelled() => break,
                    recv_res = endpoint_clone.socket.recv_from(&mut buf) => {
                        match recv_res {
                            Ok((len, addr)) => {
                                let data = &buf[..len];
                                if let Err(e) = endpoint_clone.handle_packet(data, addr).await {
                                    tracing::debug!("Packet error from {:?}: {:?}", addr, e);
                                }
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
        });

        // 2. Background Retransmission Task
        let endpoint_retransmit = endpoint.clone();
        let token_2 = shutdown_token.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = token_2.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_millis(100)) => {
                        let mut to_send_list = Vec::new();
                        {
                            let mut conns = endpoint_retransmit.connections.lock().await;
                            for conn in conns.values_mut() {
                                let now = Instant::now();
                                let mut to_remove = Vec::new();
                                let mut loss_occurred = false;
                                for (pn, (full_packet, sent_time, retries)) in conn.unacked_packets.iter_mut() {
                                    if now.duration_since(*sent_time) > conn.rtt * 4 {
                                        loss_occurred = true;
                                        if *retries > 10 {
                                            to_remove.push(*pn);
                                        } else {
                                            *sent_time = now;
                                            *retries += 1;
                                            to_send_list.push((conn.addr, full_packet.clone()));
                                        }
                                    }
                                }
                                if loss_occurred {
                                    conn.handle_loss();
                                }
                                for pn in to_remove {
                                    if let Some((packet, _, _)) = conn.unacked_packets.remove(&pn) {
                                        conn.bytes_in_flight = conn.bytes_in_flight.saturating_sub(packet.len());
                                    }
                                }
                            }
                        }
                        for (addr, packet) in to_send_list {
                            let _ = endpoint_retransmit.socket.send_to(&packet, addr).await;
                        }
                    }
                }
            }
        });

        // 3. Background Pruning Task
        let endpoint_pruner = endpoint.clone();
        let token_3 = shutdown_token.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = token_3.cancelled() => break,
                    _ = tokio::time::sleep(PRUNING_INTERVAL) => {
                        let mut conns = endpoint_pruner.connections.lock().await;
                        let now = Instant::now();
                        conns.retain(|_, conn| {
                            now.duration_since(conn.last_activity) < SESSION_EXPIRY_TIMEOUT
                        });
                        for conn in conns.values_mut() {
                            if now.duration_since(conn.last_activity) > BUFFER_CLEANUP_TIMEOUT {
                                conn.unacked_packets.clear();
                                conn.sent_shards.clear();
                            }
                        }
                    }
                }
            }
        });

        Ok(endpoint)
    }

    pub async fn get_connection_state(&self, cid: &[u8]) -> Option<(SocketAddr, Vec<u8>, Vec<u8>)> {
        let conns = self.connections.lock().await;
        conns
            .get(cid)
            .map(|c| (c.addr, c.scid.clone(), c.dcid.clone()))
    }

    pub async fn resume_connection(&self, addr: SocketAddr, scid: Vec<u8>, dcid: Vec<u8>) {
        let mut conns = self.connections.lock().await;
        let mut conn = ZtConnection::new(addr, scid.clone(), dcid);
        conn.state = ConnectionState::Active;
        conns.insert(scid, conn);
    }

    async fn handle_packet(&self, data: &[u8], addr: SocketAddr) -> Result<()> {
        if self.chaos_mode.load(Ordering::Relaxed) && rand::thread_rng().r#gen_ratio(2, 10) {
            return Ok(()); // Chaos mode: drop 20% of packets
        }

        let mut bytes = Bytes::copy_from_slice(data);
        let initial_len = bytes.remaining();
        let header = PacketHeader::decode(&mut bytes)?;
        let header_len = initial_len - bytes.remaining();
        let header_bytes = &data[..header_len];
        let payload = bytes;

        let mut conn_to_update = None;
        let mut handshake_response = None;

        {
            let mut conns = self.connections.lock().await;
            if let Some(conn) = conns.get_mut(&header.dcid) {
                conn.update_activity();
                conn.addr = addr;

                if !conn.is_replay(header.packet_number) {
                    match header.p_type {
                        PacketType::Data if conn.state == ConnectionState::Active => {
                            if let Some(ref crypto) = conn.crypto {
                                let decoded =
                                    crypto.decrypt(header.packet_number, &payload, header_bytes)?;
                                conn.mark_processed(header.packet_number);

                                conn.received_shards
                                    .insert(header.packet_number, payload.clone());
                                if conn.received_shards.len() > 4
                                    && let Some(min_pn) = conn.received_shards.keys().cloned().min()
                                    {
                                        conn.received_shards.remove(&min_pn);
                                    }

                                conn_to_update =
                                    Some((header.dcid.clone(), header.packet_number, decoded));
                            }
                        }
                        PacketType::Ack if conn.state == ConnectionState::Active => {
                            if let Some(ref crypto) = conn.crypto {
                                if crypto.decrypt(header.packet_number, &payload, header_bytes).is_ok() {
                                    conn.handle_ack(header.packet_number, header.window_size);
                                }
                            }
                        }
                        PacketType::Fec if conn.state == ConnectionState::Active => {
                            let expected_pns = [
                                header.packet_number.saturating_sub(4),
                                header.packet_number.saturating_sub(3),
                                header.packet_number.saturating_sub(2),
                                header.packet_number.saturating_sub(1),
                            ];

                            let mut missing_pn = None;
                            let mut shards_for_recovery = Vec::new();
                            for expected in &expected_pns {
                                if let Some(shard) = conn.received_shards.get(expected) {
                                    shards_for_recovery.push(shard.clone());
                                } else {
                                    missing_pn = Some(*expected);
                                }
                            }

                            if shards_for_recovery.len() == 3
                                && let Some(missing) = missing_pn
                                    && !conn.is_replay(missing) {
                                        let recovered_ciphertext =
                                            FecEngine::recover(&shards_for_recovery, &payload);

                                        let missing_header = PacketHeader {
                                            p_type: PacketType::Data,
                                            is_long: false,
                                            version: 0,
                                            dcid: header.dcid.clone(),
                                            scid: vec![],
                                            packet_number: missing,
                                            window_size: 0,
                                        };
                                        let mut buf = bytes::BytesMut::with_capacity(64);
                                        missing_header.encode(&mut buf);
                                        let reconstructed_aad = buf.freeze();

                                        if let Some(ref crypto) = conn.crypto
                                            && let Ok(dec) = crypto.decrypt(
                                                missing,
                                                &recovered_ciphertext,
                                                &reconstructed_aad,
                                            ) {
                                                conn.mark_processed(missing);
                                                conn_to_update =
                                                    Some((header.dcid.clone(), missing, dec));
                                            }
                                    }
                            conn.received_shards.clear();
                        }
                        PacketType::Handshake if payload.len() >= 32
                            && conn.state == ConnectionState::Handshaking => {
                                let mut pk_bytes = [0u8; 32];
                                pk_bytes.copy_from_slice(&payload[..32]);
                                let shared = CryptoContext::compute_shared_secret(
                                    self.static_secret.clone(),
                                    PublicKey::from(pk_bytes),
                                );
                                conn.dcid = header.scid.clone();
                                conn.crypto = Some(CryptoContext::from_shared_secret(
                                    shared, &conn.scid, &conn.dcid, self.psk,
                                ));
                                conn.state = ConnectionState::Active;
                                handshake_response =
                                    Some((header.dcid.clone(), header.packet_number));
                            }
                        PacketType::Close => {
                            if let Some(ref crypto) = conn.crypto
                                && crypto.decrypt(header.packet_number, &payload, header_bytes).is_ok()
                            {
                                conn.mark_processed(header.packet_number);
                                conn.state = ConnectionState::Closed;
                            }
                        }
                        PacketType::MtuProbe if conn.state == ConnectionState::Active => {
                            if let Some(ref crypto) = conn.crypto {
                                if crypto.decrypt(header.packet_number, &payload, header_bytes).is_ok() {
                                    conn.mark_processed(header.packet_number);
                                    // Trigger an immediate Ack response
                                    conn_to_update = Some((header.dcid.clone(), header.packet_number, vec![]));
                                }
                            }
                        }
                        _ => {}
                    }
                }
            } else if header.is_long && header.p_type == PacketType::Initial && payload.len() >= 32
            {
                let mut pk_bytes = [0u8; 32];
                pk_bytes.copy_from_slice(&payload[..32]);
                let shared = CryptoContext::compute_shared_secret(
                    self.static_secret.clone(),
                    PublicKey::from(pk_bytes),
                );
                let scid: Vec<u8> = (0..8).map(|_| rand::thread_rng().r#gen::<u8>()).collect();

                let mut new_conn = ZtConnection::new(addr, scid.clone(), header.scid);
                new_conn.crypto = Some(CryptoContext::from_shared_secret(
                    shared,
                    &new_conn.scid,
                    &new_conn.dcid,
                    self.psk,
                ));
                new_conn.state = ConnectionState::Active;
                conns.insert(scid.clone(), new_conn);

                handshake_response = Some((scid, header.packet_number));
            }
        }

        if let Some((cid, pn, decoded)) = conn_to_update {
            if !decoded.is_empty() {
                let _ = self
                    .app_tx
                    .send(ReceivedData {
                        cid: cid.clone(),
                        data: Bytes::from(decoded),
                    })
                    .await;
            }
            self.send_ack_internal(&cid, pn).await?;
        }

        if let Some((cid, pn)) = handshake_response {
            self.send_handshake_internal(&cid).await?;
            self.send_ack_internal(&cid, pn).await?;
        }

        Ok(())
    }

    async fn send_ack_internal(&self, cid: &[u8], pn: u64) -> Result<()> {
        let (addr, local_window, has_crypto) = {
            let conns = self.connections.lock().await;
            let c = conns.get(cid).ok_or(ZtError::Unauthorized)?;
            (c.addr, c.local_window, c.crypto.is_some())
        };

        let header = PacketHeader {
            p_type: PacketType::Ack,
            is_long: false,
            version: 0,
            dcid: cid.to_vec(),
            scid: vec![],
            packet_number: pn,
            window_size: local_window,
        };
        let mut buf = BytesMut::with_capacity(64);
        header.encode(&mut buf);
        let header_bytes = buf.freeze();

        let payload: &[u8] = &[];
        let encrypted = if has_crypto {
            let conns = self.connections.lock().await;
            let conn = conns.get(cid).ok_or(ZtError::Unauthorized)?;
            conn.crypto
                .as_ref()
                .ok_or_else(|| ZtError::Crypto("Crypto missing".into()))?
                .encrypt(pn, payload, &header_bytes)?
        } else {
            payload.to_vec()
        };

        let mut full_packet = BytesMut::from(&header_bytes[..]);
        full_packet.extend_from_slice(&encrypted);

        self.socket.send_to(&full_packet.freeze(), addr).await?;
        Ok(())
    }

    async fn send_handshake_internal(&self, cid: &[u8]) -> Result<()> {
        let (addr, scid, dcid, pn, local_window) = {
            let mut conns = self.connections.lock().await;
            let c = conns.get_mut(cid).ok_or(ZtError::Unauthorized)?;
            (
                c.addr,
                c.scid.clone(),
                c.dcid.clone(),
                c.get_next_packet_number()?,
                c.local_window,
            )
        };

        let header = PacketHeader {
            p_type: PacketType::Handshake,
            is_long: true,
            version: 1,
            dcid,
            scid,
            packet_number: pn,
            window_size: local_window,
        };
        let mut buf = BytesMut::with_capacity(128);
        header.encode(&mut buf);
        buf.extend_from_slice(self.public_key.as_bytes());
        self.socket.send_to(&buf, addr).await?;
        Ok(())
    }

    pub async fn connect(&self, remote_addr: SocketAddr) -> Result<Vec<u8>> {
        let scid: Vec<u8> = (0..8).map(|_| rand::thread_rng().r#gen::<u8>()).collect();
        let mut conn = ZtConnection::new(remote_addr, scid.clone(), vec![0; 8]);
        let pn = conn.get_next_packet_number()?;

        let header = PacketHeader {
            p_type: PacketType::Initial,
            is_long: true,
            version: 1,
            dcid: vec![0; 8],
            scid: scid.clone(),
            packet_number: pn,
            window_size: conn.local_window,
        };

        let mut buf = BytesMut::with_capacity(128);
        header.encode(&mut buf);
        buf.extend_from_slice(self.public_key.as_bytes());

        self.socket.send_to(&buf, remote_addr).await?;

        let mut conns = self.connections.lock().await;
        conns.insert(scid.clone(), conn);
        Ok(scid)
    }

    pub async fn send(&self, cid: &[u8], data: &[u8]) -> Result<()> {
        let (addr, pn, header_bytes, has_crypto) = {
            let mut conns = self.connections.lock().await;
            let conn = conns.get_mut(cid).ok_or(ZtError::Unauthorized)?;

            if conn.remote_window < data.len() as u32 {
                return Err(ZtError::Io(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "Flow control (Window Exhausted)",
                )));
            }
            
            if conn.bytes_in_flight + data.len() > conn.cwnd {
                return Err(ZtError::Io(std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "Congestion control (CWND Exhausted)",
                )));
            }

            let pn = conn.get_next_packet_number()?;
            let header = PacketHeader {
                p_type: PacketType::Data,
                is_long: false,
                version: 0,
                dcid: conn.dcid.clone(),
                scid: vec![],
                packet_number: pn,
                window_size: conn.local_window,
            };
            let mut buf = BytesMut::with_capacity(64);
            header.encode(&mut buf);
            (conn.addr, pn, buf.freeze(), conn.crypto.is_some())
        };

        let encrypted = if has_crypto {
            let conns = self.connections.lock().await;
            let conn = conns.get(cid).ok_or(ZtError::Unauthorized)?;
            conn.crypto
                .as_ref()
                .ok_or_else(|| ZtError::Crypto("Crypto missing".into()))?
                .encrypt(pn, data, &header_bytes)?
        } else {
            data.to_vec()
        };

        let mut full_packet = BytesMut::from(&header_bytes[..]);
        full_packet.extend_from_slice(&encrypted);
        let frozen_packet = full_packet.freeze();

        self.socket.send_to(&frozen_packet, addr).await?;

        let mut fec_packet_to_send = None;
        let mut conns = self.connections.lock().await;
        if let Some(conn) = conns.get_mut(cid) {
            conn.unacked_packets
                .insert(pn, (frozen_packet, Instant::now(), 0));
            conn.bytes_in_flight += data.len();
            conn.remote_window -= data.len() as u32;

            if has_crypto {
                conn.sent_shards.push(Bytes::from(encrypted));
                if conn.sent_shards.len() == 4 {
                    let parity = FecEngine::build_parity(&conn.sent_shards);
                    conn.sent_shards.clear();

                    let fec_pn = conn.get_next_packet_number()?;
                    let fec_header = PacketHeader {
                        p_type: PacketType::Fec,
                        is_long: false,
                        version: 0,
                        dcid: conn.dcid.clone(),
                        scid: vec![],
                        packet_number: fec_pn,
                        window_size: conn.local_window,
                    };
                    let mut buf = bytes::BytesMut::with_capacity(64);
                    fec_header.encode(&mut buf);
                    let mut full_fec = buf;
                    full_fec.extend_from_slice(&parity);
                    fec_packet_to_send = Some((conn.addr, full_fec.freeze()));
                }
            }
        }

        if let Some((addr, packet)) = fec_packet_to_send {
            self.socket.send_to(&packet, addr).await?;
        }

        Ok(())
    }

    pub async fn close(&self, cid: &[u8]) -> Result<()> {
        let (addr, pn, header_bytes, has_crypto) = {
            let mut conns = self.connections.lock().await;
            let conn = conns.get_mut(cid).ok_or(ZtError::Unauthorized)?;
            let pn = conn.get_next_packet_number()?;
            let header = PacketHeader {
                p_type: PacketType::Close,
                is_long: false,
                version: 0,
                dcid: conn.dcid.clone(),
                scid: vec![],
                packet_number: pn,
                window_size: conn.local_window,
            };
            let mut buf = BytesMut::with_capacity(64);
            header.encode(&mut buf);
            conn.state = ConnectionState::Closed;
            (conn.addr, pn, buf.freeze(), conn.crypto.is_some())
        };

        let payload: &[u8] = &[];
        let encrypted = if has_crypto {
            let conns = self.connections.lock().await;
            let conn = conns.get(cid).ok_or(ZtError::Unauthorized)?;
            conn.crypto
                .as_ref()
                .ok_or_else(|| ZtError::Crypto("Crypto missing".into()))?
                .encrypt(pn, payload, &header_bytes)?
        } else {
            payload.to_vec()
        };

        let mut full_packet = BytesMut::from(&header_bytes[..]);
        full_packet.extend_from_slice(&encrypted);
        self.socket.send_to(&full_packet.freeze(), addr).await?;

        // Immediately remove it from the map
        let mut conns = self.connections.lock().await;
        conns.remove(cid);

        Ok(())
    }

    pub async fn recv(&self) -> Option<ReceivedData> {
        let mut rx = self.app_rx.lock().await;
        rx.recv().await
    }

    pub fn set_chaos_mode(&self, enabled: bool) {
        self.chaos_mode.store(enabled, Ordering::Relaxed);
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.socket.local_addr().map_err(ZtError::Io)
    }
}

impl Drop for ZtEndpoint {
    fn drop(&mut self) {
        self.shutdown_token.cancel();
    }
}
