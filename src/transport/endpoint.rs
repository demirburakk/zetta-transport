use crate::crypto::CryptoContext;
use crate::error::{Result, ZtError};
use crate::protocol::packet::{PacketHeader, PacketType};
use crate::transport::actor::{ActorMessage, ZtConnectionActor};
use crate::transport::state::{ConnectionState, ZtConnection, StreamState};
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Mutex, Notify};
use x25519_dalek::{PublicKey, StaticSecret};

pub struct ZtEndpoint {
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) routing_table: Arc<DashMap<Vec<u8>, mpsc::Sender<ActorMessage>>>,
    pub(crate) static_secret: StaticSecret,
    pub public_key: PublicKey,
    pub psk: Option<[u8; 32]>,
    pub cookie_key: [u8; 32], 
    
    incoming_rx: Mutex<mpsc::Receiver<crate::stream::ZtStream>>,
    pub(crate) incoming_tx: mpsc::Sender<crate::stream::ZtStream>,
}

impl ZtEndpoint {
    pub async fn bind(addr: &str, psk: Option<[u8; 32]>) -> Result<Arc<Self>> {
        let (secret, public) = CryptoContext::generate_keypair();
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        let (tx, rx) = mpsc::channel(1024);
        let cookie_key = rand::thread_rng().r#gen::<[u8; 32]>();

        let endpoint = Arc::new(Self {
            socket,
            routing_table: Arc::new(DashMap::new()),
            static_secret: secret,
            public_key: public,
            psk,
            cookie_key,
            incoming_rx: Mutex::new(rx),
            incoming_tx: tx,
        });

        Self::start_router(endpoint.clone());
        Ok(endpoint)
    }

    fn start_router(endpoint: Arc<Self>) {
        tokio::spawn(async move {
            let mut buf = [0u8; 2048]; // Handle padded initial packets
            loop {
                if let Ok((len, addr)) = endpoint.socket.recv_from(&mut buf).await {
                    let data = Bytes::copy_from_slice(&buf[..len]);

                    if let Some(dcid) = Self::extract_dcid_fast(&data) {
                        if let Some(tx) = endpoint.routing_table.get(&dcid) {
                            if let Err(_e) = tx.try_send(ActorMessage::IncomingPacket { data, addr }) {
                                tracing::trace!("Dropped packet for {:?}: queue full", dcid);
                            }
                        } else {
                            let ep_clone = endpoint.clone();
                            tokio::spawn(async move {
                                if let Err(e) = ep_clone.clone().handle_handshake(data, addr).await {
                                    tracing::debug!("Handshake failed: {:?}", e);
                                }
                            });
                        }
                    }
                }
            }
        });
    }

    async fn handle_handshake(self: Arc<Self>, mut data: Bytes, addr: SocketAddr) -> Result<()> {
        if data.len() < 1200 {
            return Ok(()); // Anti-amplification drop
        }
        
        let mut mutable_packet = data.to_vec();
        // Remove Header Protection from the incoming Initial packet
        if let Some(offset) = PacketHeader::get_pn_offset(&mutable_packet) {
            let dcid_opt = Self::extract_dcid_fast(&mutable_packet);
            if let Some(dcid) = dcid_opt {
                let crypto = CryptoContext::initial(&dcid);
                crypto.remove_header_protection(&mut mutable_packet, offset)?;
            }
        }
        data = Bytes::from(mutable_packet);
        
        let header = PacketHeader::decode(&mut data)?;

        if !header.is_long || header.p_type != PacketType::Initial {
            return Ok(());
        }

        let payload = data;
        if payload.len() < 32 { return Ok(()); }

        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&payload[..32]);

        let current_time = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

        let mut is_cookie_valid = false;
        if payload.len() >= 72 {
            let mut timestamp_bytes = [0u8; 8];
            timestamp_bytes.copy_from_slice(&payload[32..40]);
            let timestamp = u64::from_be_bytes(timestamp_bytes);
            
            if current_time >= timestamp && current_time - timestamp <= 5 {
                let mut hasher = Sha256::new();
                hasher.update(&self.cookie_key);
                match addr.ip() {
                    std::net::IpAddr::V4(v4) => hasher.update(&v4.octets()),
                    std::net::IpAddr::V6(v6) => hasher.update(&v6.octets()),
                }
                hasher.update(&addr.port().to_be_bytes());
                hasher.update(&header.scid);
                hasher.update(&timestamp_bytes);
                let expected_hash = hasher.finalize();

                if payload[40..72] == expected_hash[..] {
                    is_cookie_valid = true;
                }
            }
        }

        if is_cookie_valid {
            let shared = CryptoContext::compute_shared_secret(
                self.static_secret.clone(),
                PublicKey::from(pk_bytes),
            );

            let mut scid: Vec<u8> = (0..8).map(|_| rand::thread_rng().r#gen::<u8>()).collect();
            while self.routing_table.contains_key(&scid) {
                scid = (0..8).map(|_| rand::thread_rng().r#gen::<u8>()).collect();
            }
            let mut new_conn = ZtConnection::new(addr, scid.clone(), header.scid.clone());
            
            let (data_tx, data_rx) = mpsc::channel(2048);
            let window_opened = Arc::new(Notify::new());
            new_conn.streams.insert(0, StreamState::new(data_tx, window_opened.clone()));

            let handshake_pn = new_conn.get_next_packet_number()?;
            new_conn.mark_processed(header.packet_number);
            new_conn.state = ConnectionState::Active;

            new_conn.crypto = Some(CryptoContext::from_shared_secret(
                shared, &new_conn.scid, &new_conn.dcid, self.psk,
            ));

            let (actor_tx, actor_rx) = mpsc::channel(1024);

            let actor = ZtConnectionActor {
                socket: self.socket.clone(),
                receiver: actor_rx,
                state: new_conn,
                pending_acks: 0,
                public_key: self.public_key,
                static_secret: self.static_secret.clone(),
                psk: self.psk,
                handshake_waiter: None,
                routing_table: self.routing_table.clone(), 
                scid: scid.clone(),
                last_active_stream_id: 0,
            };

            self.routing_table.insert(scid.clone(), actor_tx);
            tokio::spawn(actor.run());

            let stream = crate::stream::ZtStream::new(self.clone(), scid.clone(), 0, data_rx, window_opened);

            if let Err(_) = self.incoming_tx.try_send(stream) {
                tracing::warn!("Server accept queue is full. Dropping incoming connection from {:?}", addr);
                self.routing_table.remove(&scid);
                return Ok(());
            }

            let hs_header = PacketHeader {
                p_type: PacketType::Handshake,
                is_long: true,
                version: 1,
                dcid: header.scid.clone(),
                scid,
                packet_number: handshake_pn,
                window_size: 1024 * 1024,
                stream_id: 0,
                offset: 0,
                acked_pn: 0,
            };
            let mut buf = BytesMut::with_capacity(128);
            hs_header.encode(&mut buf);
            buf.extend_from_slice(self.public_key.as_bytes());
            let mut buf_vec = buf.to_vec();
            if let Some(offset) = PacketHeader::get_pn_offset(&buf_vec) {
                let crypto = CryptoContext::initial(&header.dcid);
                crypto.apply_header_protection(&mut buf_vec, offset)?;
            }
            if let Err(e) = self.socket.try_send_to(&buf_vec, addr) {
                tracing::debug!("Failed to send: {}", e);
            }
        } else {
            let mut hasher = Sha256::new();
            hasher.update(&self.cookie_key);
            match addr.ip() {
                std::net::IpAddr::V4(v4) => hasher.update(&v4.octets()),
                std::net::IpAddr::V6(v6) => hasher.update(&v6.octets()),
            }
            hasher.update(&addr.port().to_be_bytes());
            hasher.update(&header.scid);
            let time_bytes = current_time.to_be_bytes();
            hasher.update(&time_bytes);
            let cookie_hash = hasher.finalize();

            let mut new_cookie = vec![0u8; 40];
            new_cookie[0..8].copy_from_slice(&time_bytes);
            new_cookie[8..40].copy_from_slice(&cookie_hash);

            let retry_header = PacketHeader {
                p_type: PacketType::Retry,
                is_long: true,
                version: 1,
                dcid: header.scid.clone(),
                scid: vec![],
                packet_number: header.packet_number,
                window_size: 0,
                stream_id: 0,
                offset: 0,
                acked_pn: 0,
            };
            let mut buf = BytesMut::with_capacity(128);
            retry_header.encode(&mut buf);
            buf.extend_from_slice(&new_cookie);
            let mut buf_vec = buf.to_vec();
            if let Some(offset) = PacketHeader::get_pn_offset(&buf_vec) {
                let crypto = CryptoContext::initial(&header.dcid);
                crypto.apply_header_protection(&mut buf_vec, offset)?;
            }
            if let Err(e) = self.socket.try_send_to(&buf_vec, addr) {
                tracing::debug!("Failed to send: {}", e);
            }
        }
        Ok(())
    }

    fn extract_dcid_fast(data: &[u8]) -> Option<Vec<u8>> {
        if data.is_empty() { return None; }
        let is_long = (data[0] & 0x80) != 0;

        if is_long {
            if data.len() < 6 { return None; }
            let dcid_len = data[5] as usize;
            if data.len() < 6 + dcid_len { return None; }
            Some(data[6..6 + dcid_len].to_vec())
        } else {
            if data.len() < 2 { return None; }
            let dcid_len = data[1] as usize;
            if data.len() < 2 + dcid_len { return None; }
            Some(data[2..2 + dcid_len].to_vec())
        }
    }

    /// Fetches the dynamic MTU of a specific connection.
    pub async fn get_mtu(&self, cid: &[u8]) -> usize {
        if let Some(tx) = self.routing_table.get(cid) {
            let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
            if tx.send(ActorMessage::GetMtu { respond_to: resp_tx }).await.is_ok() {
                return resp_rx.await.unwrap_or(1200);
            }
        }
        1200
    }

    /// Internal method used by ZtStream to send data to the remote endpoint.
    pub async fn send(&self, cid: &[u8], stream_id: u32, data: &[u8]) -> Result<()> {
        if let Some(tx) = self.routing_table.get(cid) {
            let (resp_tx, resp_rx) = oneshot::channel();
            tx.send(ActorMessage::OutgoingData {
                stream_id,
                data: Bytes::copy_from_slice(data),
                respond_to: resp_tx
            }).await.map_err(|_| ZtError::Unknown)?;
            return resp_rx.await.unwrap_or(Err(ZtError::Unknown));
        }
        Err(ZtError::Unknown)
    }

    /// Gracefully closes a stream within a connection.
    pub async fn close_stream(&self, cid: &[u8], stream_id: u32) -> Result<()> {
        if let Some(tx) = self.routing_table.get(cid) {
            let _ = tx.send(ActorMessage::CloseStream { stream_id }).await;
        }
        Ok(())
    }

    /// Gracefully closes a connection associated with the given Connection ID (CID).
    pub async fn close(&self, cid: &[u8]) -> Result<()> {
        if let Some((_, tx)) = self.routing_table.remove(cid) {
            let _ = tx.send(ActorMessage::Close).await;
        }
        Ok(())
    }

    /// Accepts an incoming connection from a remote peer.
    /// Returns a `ZtStream` representing the reliable data channel.
    pub async fn accept(&self) -> Option<crate::stream::ZtStream> {
        let mut rx = self.incoming_rx.lock().await;
        rx.recv().await
    }

    /// Connects to a remote ZtEndpoint at the specified address.
    /// Performs a secure handshake and returns a `ZtStream` upon success.
    pub async fn connect(self: &Arc<Self>, addr: SocketAddr) -> Result<crate::stream::ZtStream> {
        let scid: Vec<u8> = (0..8).map(|_| rand::thread_rng().r#gen::<u8>()).collect();
        let dcid = vec![0u8; 8]; 
        
        let mut conn = ZtConnection::new(addr, scid.clone(), dcid);
        conn.state = ConnectionState::Handshaking;

        let (data_tx, data_rx) = mpsc::channel(2048);
        let window_opened = Arc::new(Notify::new());
        conn.streams.insert(0, StreamState::new(data_tx, window_opened.clone()));

        let (actor_tx, actor_rx) = mpsc::channel(1024);
        
        let (wait_tx, wait_rx) = oneshot::channel();

        let actor = ZtConnectionActor {
            socket: self.socket.clone(),
            receiver: actor_rx,
            state: conn,
            pending_acks: 0,
            public_key: self.public_key,
            static_secret: self.static_secret.clone(),
            psk: self.psk,
            handshake_waiter: Some(wait_tx),
            routing_table: self.routing_table.clone(),
            scid: scid.clone(),
            last_active_stream_id: 0,
        };

        self.routing_table.insert(scid.clone(), actor_tx);
        tokio::spawn(actor.run());

        match tokio::time::timeout(std::time::Duration::from_secs(5), wait_rx).await {
            Ok(Ok(_)) => Ok(crate::stream::ZtStream::new(self.clone(), scid, 0, data_rx, window_opened)),
            _ => {
                self.routing_table.remove(&scid);
                Err(ZtError::Timeout)
            }
        }
    }
}