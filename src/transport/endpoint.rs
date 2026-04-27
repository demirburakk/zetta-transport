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
        let header = PacketHeader::decode(&mut data)?;

        if !header.is_long || header.p_type != PacketType::Initial {
            return Ok(());
        }

        let payload = data;
        if payload.len() < 32 { return Ok(()); }

        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(&payload[..32]);

        let mut hasher = Sha256::new();
        hasher.update(&self.cookie_key); 
        hasher.update(addr.to_string().as_bytes());
        hasher.update(&header.scid);
        let expected_cookie = hasher.finalize();

        if payload.len() >= 64 && payload[32..64] == expected_cookie[..] {
            let shared = CryptoContext::compute_shared_secret(
                self.static_secret.clone(),
                PublicKey::from(pk_bytes),
            );

            let scid: Vec<u8> = (0..8).map(|_| rand::thread_rng().r#gen::<u8>()).collect();
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
            let _ = self.socket.try_send_to(&buf, addr);

        } else {
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
            buf.extend_from_slice(&expected_cookie);
            let _ = self.socket.try_send_to(&buf, addr);
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
