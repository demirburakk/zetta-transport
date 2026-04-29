use crate::crypto::CryptoContext;
use crate::error::{Result, ZtError};
use crate::protocol::packet::{PacketHeader, PacketType};
use crate::protocol::frame::Frame;
use crate::transport::actor::{ActorMessage, ZtConnectionActor};
use crate::transport::state::{ConnectionState, ZtConnection, StreamState};
use bytes::{Bytes, BytesMut, Buf, BufMut};
use dashmap::DashMap;
use rand::Rng;
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Mutex, Notify, Semaphore};
use x25519_dalek::{PublicKey, StaticSecret};
use ed25519_dalek::{SigningKey, Signer, VerifyingKey, Signature, Verifier};

pub struct ZtEndpoint {
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) routing_table: Arc<DashMap<Vec<u8>, mpsc::Sender<ActorMessage>>>,
    pub(crate) static_secret: StaticSecret,
    pub public_key: PublicKey,
    pub ed_signing_key: SigningKey,
    pub ed_public_key: VerifyingKey,
    pub psk: Option<[u8; 32]>,
    pub cookie_key: [u8; 32], 
    handshake_semaphore: Arc<Semaphore>,
    
    incoming_rx: Mutex<mpsc::Receiver<crate::stream::ZtStream>>,
    pub(crate) incoming_tx: mpsc::Sender<crate::stream::ZtStream>,
}

impl ZtEndpoint {
    pub async fn bind(addr: &str, psk: Option<[u8; 32]>) -> Result<Arc<Self>> {
        let (secret, public) = CryptoContext::generate_keypair();
        
        let mut csprng = rand::rngs::OsRng;
        let ed_signing_key = SigningKey::generate(&mut csprng);
        let ed_public_key = ed_signing_key.verifying_key();

        let socket = Arc::new(UdpSocket::bind(addr).await?);
        let (tx, rx) = mpsc::channel(1024);
        let cookie_key = rand::thread_rng().r#gen::<[u8; 32]>();

        let endpoint = Arc::new(Self {
            socket,
            routing_table: Arc::new(DashMap::new()),
            static_secret: secret,
            public_key: public,
            ed_signing_key,
            ed_public_key,
            psk,
            cookie_key,
            handshake_semaphore: Arc::new(Semaphore::new(256)),
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
                            // Prevent unbounded task spawning on spoofed/unknown DCIDs.
                            let permit = match endpoint.handshake_semaphore.clone().try_acquire_owned() {
                                Ok(p) => p,
                                Err(_) => {
                                    tracing::debug!("Handshake shed load: too many concurrent attempts");
                                    continue;
                                }
                            };

                            let ep_clone = endpoint.clone();
                            tokio::spawn(async move {
                                let _permit = permit;
                                if let Err(e) = ep_clone.handle_handshake(data, addr).await {
                                    tracing::debug!("Handshake failed: {:?}", e);
                                }
                            });
                        }
                    }
                }
            }
        });
    }

    async fn handle_handshake(self: Arc<Self>, data: Bytes, addr: SocketAddr) -> Result<()> {
        if data.len() < 1200 {
            return Ok(()); // Anti-amplification drop
        }
        
        let mut mutable_packet = data.to_vec();
        // Remove Header Protection from the incoming Initial packet
        if let Some(offset) = PacketHeader::get_pn_offset(&mutable_packet) {
            let dcid_opt = Self::extract_dcid_fast(&mutable_packet);
            if let Some(dcid) = dcid_opt {
                let crypto = CryptoContext::initial(&dcid, false);
                crypto.remove_header_protection(&mut mutable_packet, offset, false)?;
            }
        }
        let original_data = Bytes::from(mutable_packet);
        let mut data_cursor = original_data.clone();
        let initial_len = data_cursor.remaining();
        
        let header = PacketHeader::decode(&mut data_cursor)?;
        let header_len = initial_len - data_cursor.remaining();
        let aad = &original_data[..header_len];

        if !header.is_long || header.p_type != PacketType::Initial {
            return Ok(());
        }

        let mut payload = data_cursor.to_vec();
        if payload.len() < 16 { return Ok(()); }
        let tag_bytes = payload.split_off(payload.len() - 16);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&tag_bytes);
        
        let crypto = CryptoContext::initial(&header.dcid, false);
        if crypto.decrypt_in_place(header.packet_number, aad, &mut payload, &tag, false).is_err() {
            return Ok(());
        }
        
        let mut payload_bytes = Bytes::from(payload);
        let mut pk_bytes = [0u8; 32];
        let mut remote_ed_pk_bytes = [0u8; 32];
        let mut remote_sig_bytes = [0u8; 64];
        
        let mut cookie: Option<Bytes> = None;
        let mut handshake_found = false;

        while payload_bytes.remaining() > 0 {
            match Frame::decode(&mut payload_bytes) {
                Ok(Frame::Handshake { public_key, ed_public_key, signature }) => {
                    pk_bytes = public_key;
                    remote_ed_pk_bytes = ed_public_key;
                    remote_sig_bytes = signature;
                    handshake_found = true;
                }
                Ok(Frame::Cookie { cookie: c }) => {
                    cookie = Some(c);
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }

        if !handshake_found {
            return Ok(());
        }

        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let is_cookie_valid = cookie
            .as_deref()
            .is_some_and(|c| self.verify_retry_cookie(&addr, &header.scid, c, current_time));

        if !is_cookie_valid {
            let new_cookie = self.make_retry_cookie(&addr, &header.scid, current_time);
            self.send_retry(addr, &header.scid, header.packet_number, &new_cookie)?;
            return Ok(());
        }

        {
            // Verify Ed25519 signature
            let remote_ed_pk = VerifyingKey::from_bytes(&remote_ed_pk_bytes)
                .map_err(|_| ZtError::Crypto("Invalid Ed25519 Public Key".into()))?;
            let remote_sig = Signature::from_bytes(&remote_sig_bytes);
            
            remote_ed_pk.verify(&pk_bytes, &remote_sig)
                .map_err(|_| ZtError::Crypto("Invalid Handshake Signature".into()))?;

            let shared = CryptoContext::compute_shared_secret(
                self.static_secret.clone(),
                PublicKey::from(pk_bytes),
            );

            let mut scid: Vec<u8> = (0..8).map(|_| rand::thread_rng().r#gen::<u8>()).collect();
            while self.routing_table.contains_key(&scid) {
                scid = (0..8).map(|_| rand::thread_rng().r#gen::<u8>()).collect();
            }
            let mut new_conn = ZtConnection::new(addr, scid.clone(), header.scid.clone());
            new_conn.bytes_received = original_data.len();
            
            let (data_tx, data_rx) = mpsc::channel(2048);
            let window_opened = Arc::new(Notify::new());
            new_conn.streams.insert(0, StreamState::new(data_tx, window_opened.clone()));

            let handshake_pn = new_conn.get_next_packet_number()?;
            new_conn.mark_processed(header.packet_number);
            new_conn.state = ConnectionState::Active;

            new_conn.crypto = Some(CryptoContext::from_shared_secret(
                shared, &new_conn.scid, &new_conn.dcid, self.psk, false,
            ));

            let (actor_tx, actor_rx) = mpsc::channel(1024);

            let actor = ZtConnectionActor {
                socket: self.socket.clone(),
                receiver: actor_rx,
                state: new_conn,
                pending_acks: 0,
                public_key: self.public_key,
                static_secret: self.static_secret.clone(),
                ed_signing_key: self.ed_signing_key.clone(),
                ed_public_key: self.ed_public_key,
                psk: self.psk,
                handshake_waiter: None,
                routing_table: self.routing_table.clone(), 
                scid: scid.clone(),
                last_active_stream_id: 0,
            };

            self.routing_table.insert(scid.clone(), actor_tx);
            tokio::spawn(actor.run());

            let stream = crate::stream::ZtStream::new(self.clone(), scid.clone(), 0, data_rx, window_opened);

            if self.incoming_tx.try_send(stream).is_err() {
                tracing::warn!("Server accept queue is full. Dropping incoming connection from {:?}", addr);
                self.routing_table.remove(&scid);
                return Ok(());
            }

            let hs_header = PacketHeader {
                p_type: PacketType::Handshake,
                is_long: true,
                version: 1,
                dcid: header.scid.clone(),
                scid: scid.clone(),
                packet_number: handshake_pn,
                key_phase: false,
            };
            let mut buf = BytesMut::with_capacity(256);
            hs_header.encode(&mut buf);
            let header_len = buf.len();
            
            let frame = Frame::Handshake {
                public_key: *self.public_key.as_bytes(),
                ed_public_key: *self.ed_public_key.as_bytes(),
                signature: self.ed_signing_key.sign(self.public_key.as_bytes()).to_bytes(),
            };
            frame.encode(&mut buf);
            let payload_len = buf.len() - header_len;
            buf.put_bytes(0, 16); // tag
            
            let crypto = CryptoContext::initial(&hs_header.dcid, false);
            {
                let packet_slice = buf.as_mut();
                let (aad, rest) = packet_slice.split_at_mut(header_len);
                let (payload, tag_space) = rest.split_at_mut(payload_len);
                if let Ok(tag) = crypto.encrypt_in_place(handshake_pn, aad, payload) {
                    tag_space.copy_from_slice(&tag);
                }
            }

            let packet_slice = buf.as_mut();
            if let Some(offset) = PacketHeader::get_pn_offset(packet_slice) {
                let (header_part, payload_part) = packet_slice.split_at_mut(header_len);
                let _ = crypto.apply_header_protection(header_part, payload_part, offset);
            }
            if let Err(e) = self.socket.try_send_to(packet_slice, addr) {
                tracing::debug!("Failed to send: {}", e);
            }
        }
        Ok(())
    }

    fn make_retry_cookie(&self, addr: &SocketAddr, client_scid: &[u8], now: u64) -> [u8; 40] {
        let mut hasher = Sha256::new();
        hasher.update(self.cookie_key);
        match addr.ip() {
            std::net::IpAddr::V4(v4) => hasher.update(v4.octets()),
            std::net::IpAddr::V6(v6) => hasher.update(v6.octets()),
        }
        hasher.update(addr.port().to_be_bytes());
        hasher.update(client_scid);
        let time_bytes = now.to_be_bytes();
        hasher.update(time_bytes);
        let cookie_hash = hasher.finalize();

        let mut cookie = [0u8; 40];
        cookie[0..8].copy_from_slice(&time_bytes);
        cookie[8..40].copy_from_slice(&cookie_hash);
        cookie
    }

    fn verify_retry_cookie(&self, addr: &SocketAddr, client_scid: &[u8], cookie: &[u8], now: u64) -> bool {
        if cookie.len() != 40 {
            return false;
        }
        let mut time_bytes = [0u8; 8];
        time_bytes.copy_from_slice(&cookie[0..8]);
        let cookie_time = u64::from_be_bytes(time_bytes);

        // Accept cookies issued in the last 30 seconds.
        if now < cookie_time || now - cookie_time > 30 {
            return false;
        }

        let expected = self.make_retry_cookie(addr, client_scid, cookie_time);
        expected[8..40] == cookie[8..40]
    }

    fn send_retry(&self, addr: SocketAddr, client_scid: &[u8], packet_number: u64, cookie: &[u8; 40]) -> Result<()> {
        let retry_header = PacketHeader {
            p_type: PacketType::Retry,
            is_long: true,
            version: 1,
            dcid: client_scid.to_vec(),
            scid: vec![],
            packet_number,
            key_phase: false,
        };

        let mut buf = BytesMut::with_capacity(128);
        retry_header.encode(&mut buf);
        let header_len = buf.len();
        buf.extend_from_slice(cookie);

        let mut buf_vec = buf.to_vec();
        if let Some(offset) = PacketHeader::get_pn_offset(&buf_vec) {
            let crypto = CryptoContext::initial(client_scid, false);
            let (header_part, payload_part) = buf_vec.split_at_mut(header_len);
            crypto.apply_header_protection(header_part, payload_part, offset)?;
        }

        if let Err(e) = self.socket.try_send_to(&buf_vec, addr) {
            tracing::debug!("Failed to send: {}", e);
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

    pub async fn get_mtu(&self, cid: &[u8]) -> usize {
        if let Some(tx) = self.routing_table.get(cid) {
            let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
            if tx.send(ActorMessage::GetMtu { respond_to: resp_tx }).await.is_ok() {
                return resp_rx.await.unwrap_or(1200);
            }
        }
        1200
    }

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

    pub async fn close_stream(&self, cid: &[u8], stream_id: u32) -> Result<()> {
        if let Some(tx) = self.routing_table.get(cid) {
            let _ = tx.send(ActorMessage::CloseStream { stream_id }).await;
        }
        Ok(())
    }

    pub async fn close(&self, cid: &[u8]) -> Result<()> {
        if let Some((_, tx)) = self.routing_table.remove(cid) {
            let _ = tx.send(ActorMessage::Close).await;
        }
        Ok(())
    }

    pub async fn accept(&self) -> Option<crate::stream::ZtStream> {
        let mut rx = self.incoming_rx.lock().await;
        rx.recv().await
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }

    pub async fn connect(self: &Arc<Self>, addr: SocketAddr) -> Result<crate::stream::ZtStream> {
        let scid: Vec<u8> = (0..8).map(|_| rand::thread_rng().r#gen::<u8>()).collect();
        let dcid = vec![0u8; 8]; 
        
        let mut conn = ZtConnection::new(addr, scid.clone(), dcid);
        conn.bytes_received = 1000000; // Client is not subject to amplification limits
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
            ed_signing_key: self.ed_signing_key.clone(),
            ed_public_key: self.ed_public_key,
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