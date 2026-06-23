use crate::error::{Result, ZtError};
use crate::stream::{ZtConnectionHandle, ZtStream};
use crate::transport::actor::{ActorMessage, ZtConnectionActor};
use crate::transport::connection::ZtConnection;
use crate::transport::state::ConnectionState;
use bytes::Bytes;
use dashmap::DashMap;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::Rng;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, Semaphore, mpsc, oneshot};

const MAX_ACTIVE_CONNECTIONS: usize = 1000;

/// Type alias for the optional peer key verification callback.
pub type PeerKeyVerifier = Arc<dyn Fn(&[u8; 32]) -> bool + Send + Sync>;

/// The main entry point for the ZettaTransport protocol.
///
/// An endpoint binds to a local UDP address and can both accept incoming
/// connections and initiate outgoing connections. All per-connection state
/// is managed by spawned actor tasks.
pub struct ZtEndpoint {
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) routing_table: Arc<DashMap<Vec<u8>, mpsc::Sender<ActorMessage>>>,
    // Signing key must stay private; only the verifying key is shared.
    pub(crate) ed_signing_key: SigningKey,
    pub ed_public_key: VerifyingKey,
    pub(crate) psk: Option<[u8; 32]>,
    pub(crate) cookie_key: [u8; 32],
    pub verify_peer_key: Option<PeerKeyVerifier>,
    pub(crate) handshake_semaphore: Arc<Semaphore>,
    pub(crate) handshake_replay_filter: Arc<DashMap<[u8; 32], u64>>,
    pub(crate) cc_algo: crate::transport::congestion::CongestionControlAlgorithm,
    pub(crate) alpn: std::sync::RwLock<Vec<u8>>,

    incoming_rx: Mutex<mpsc::Receiver<ZtConnectionHandle>>,
    pub(crate) incoming_tx: mpsc::Sender<ZtConnectionHandle>,
}

impl ZtEndpoint {
    /// Binds an endpoint to the given local address, defaulting to the `Cubic`
    /// congestion control algorithm.
    pub async fn bind(addr: &str, psk: Option<[u8; 32]>) -> Result<Arc<Self>> {
        Self::bind_with_config(addr, psk, crate::transport::congestion::CongestionControlAlgorithm::Cubic).await
    }

    /// Binds an endpoint with the specified configuration, including a custom
    /// pre-shared key (PSK) and selection of the pluggable congestion control algorithm.
    ///
    /// The specified `cc_algo` (e.g. `Cubic` or `Reno`) will govern the transmission rate
    /// and backpressure management of all connections accepted or initiated by this endpoint.
    pub async fn bind_with_config(
        addr: &str,
        psk: Option<[u8; 32]>,
        cc_algo: crate::transport::congestion::CongestionControlAlgorithm,
    ) -> Result<Arc<Self>> {
        let mut csprng = rand::rngs::OsRng;
        let ed_signing_key = SigningKey::generate(&mut csprng);
        let ed_public_key = ed_signing_key.verifying_key();

        let socket_addr: SocketAddr = addr.parse().map_err(|e| std::io::Error::other(format!("Invalid address: {}", e)))?;
        let cookie_key = rand::thread_rng().r#gen::<[u8; 32]>();
        let (tx, rx) = mpsc::channel(1024);

        // Bind main socket
        let domain = match socket_addr {
            SocketAddr::V4(_) => socket2::Domain::IPV4,
            SocketAddr::V6(_) => socket2::Domain::IPV6,
        };
        let std_socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
        std_socket.set_reuse_port(true)?;
        
        let buf_size = 2 * 1024 * 1024;
        if let Err(e) = std_socket.set_recv_buffer_size(buf_size) {
            tracing::debug!("Failed to set socket receive buffer size to {}: {:?}", buf_size, e);
            let _ = std_socket.set_recv_buffer_size(256 * 1024);
        }
        if let Err(e) = std_socket.set_send_buffer_size(buf_size) {
            tracing::debug!("Failed to set socket send buffer size to {}: {:?}", buf_size, e);
            let _ = std_socket.set_send_buffer_size(256 * 1024);
        }

        std_socket.set_nonblocking(true)?;
        std_socket.bind(&socket_addr.into())?;
        
        let actual_addr: SocketAddr = std_socket
            .local_addr()?
            .as_socket()
            .ok_or_else(|| std::io::Error::other("Failed to resolve local socket addr"))?;
        
        let socket = Arc::new(UdpSocket::from_std(std_socket.into())?);

        let endpoint = Arc::new(Self {
            socket: socket.clone(),
            routing_table: Arc::new(DashMap::new()),
            ed_signing_key,
            ed_public_key,
            psk,
            cookie_key,
            verify_peer_key: None,
            handshake_semaphore: Arc::new(Semaphore::new(256)),
            handshake_replay_filter: Arc::new(DashMap::new()),
            incoming_rx: Mutex::new(rx),
            incoming_tx: tx,
            cc_algo,
            alpn: std::sync::RwLock::new(b"zetta".to_vec()),
        });

        // Main socket routing
        Self::start_router(endpoint.clone(), socket.clone());

        let cores = num_cpus::get();
        // Since we already have 1 task on main socket, start cores - 1 more
        for _ in 1..cores {
            let task_socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
            #[cfg(unix)]
            task_socket.set_reuse_port(true)?;
            #[cfg(not(unix))]
            task_socket.set_reuse_address(true)?;

            let buf_size = 2 * 1024 * 1024;
            if let Err(e) = task_socket.set_recv_buffer_size(buf_size) {
                tracing::debug!("Failed to set task socket receive buffer size to {}: {:?}", buf_size, e);
                let _ = task_socket.set_recv_buffer_size(256 * 1024);
            }
            if let Err(e) = task_socket.set_send_buffer_size(buf_size) {
                tracing::debug!("Failed to set task socket send buffer size to {}: {:?}", buf_size, e);
                let _ = task_socket.set_send_buffer_size(256 * 1024);
            }

            task_socket.set_nonblocking(true)?;
            task_socket.bind(&actual_addr.into())?;
            let tokio_socket = Arc::new(UdpSocket::from_std(task_socket.into())?);
            Self::start_router(endpoint.clone(), tokio_socket);
        }
        
        Ok(endpoint)
    }

    /// Starts the packet router task that dispatches incoming datagrams
    /// to the correct per-connection actor or initiates new handshakes.
    fn start_router(endpoint: Arc<Self>, socket: Arc<UdpSocket>) {
        tokio::spawn(async move {
            let mut local_routing_table = std::collections::HashMap::new();
            let mut buf = bytes::BytesMut::zeroed(2048);
            loop {
                let mut processed = 0;
                while processed < 64 {
                    let recv_result = socket.try_recv_from(&mut buf);
                    let (len, addr) = match recv_result {
                        Ok(res) => res,
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            if processed == 0 {
                                match socket.recv_from(&mut buf).await {
                                    Ok(res) => res,
                                    Err(_) => break,
                                }
                            } else {
                                break;
                            }
                        }
                        Err(_) => break,
                    };

                    let data = buf.split_to(len);
                    if buf.capacity() < 2048 {
                        buf = bytes::BytesMut::zeroed(2048);
                    } else {
                        buf.resize(2048, 0);
                    }

                    if let Some(dcid) = crate::protocol::routing::extract_dcid_fast(&data) {
                        let mut routed = false;
                        if let Some(tx) = local_routing_table.get(&dcid) {
                            let tx: &mpsc::Sender<ActorMessage> = tx;
                            if tx.is_closed() {
                                local_routing_table.remove(&dcid);
                            } else if tx.try_send(ActorMessage::IncomingPacket { data: data.clone(), addr }).is_ok() {
                                routed = true;
                            } else {
                                tracing::debug!("Local routing cache try_send failed for dcid, removing from cache");
                                local_routing_table.remove(&dcid);
                            }
                        }
                        
                        if !routed {
                            if let Some(tx) = endpoint.routing_table.get(&dcid) {
                                if tx.is_closed() {
                                    drop(tx);
                                    endpoint.routing_table.remove(&dcid);
                                } else {
                                    local_routing_table.insert(dcid.clone(), tx.clone());
                                    let _ = tx.try_send(ActorMessage::IncomingPacket { data, addr });
                                }
                            } else {
                                let is_initial = data.len() >= 1200
                                    && (data[0] & 0x80) != 0;

                                if is_initial {
                                    if endpoint.routing_table.len() >= MAX_ACTIVE_CONNECTIONS {
                                        tracing::warn!("Dropped incoming handshake: server at maximum connection capacity");
                                    } else if let Ok(permit) = endpoint.handshake_semaphore.clone().try_acquire_owned() {
                                        let ep_clone = endpoint.clone();
                                        tokio::spawn(async move {
                                            let _permit = permit;
                                            if let Err(e) = crate::transport::handshake::handle_handshake(
                                                ep_clone,
                                                data.freeze(),
                                                addr,
                                            )
                                            .await
                                            {
                                                tracing::debug!("Handshake failed: {:?}", e);
                                            }
                                        });
                                    } else {
                                        tracing::debug!("Dropped incoming handshake: server at capacity");
                                    }
                                }
                            }
                        }
                    }
                    processed += 1;
                }
            }
        });
    }

    /// Sets the ALPN protocols supported by this endpoint.
    pub fn set_alpn(&self, alpn: Vec<u8>) {
        if let Ok(mut guard) = self.alpn.write() {
            *guard = alpn;
        }
    }

    /// Returns the MTU for a given connection.
    pub async fn get_mtu(&self, cid: &[u8]) -> usize {
        if let Some(tx) = self.routing_table.get(cid) {
            let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
            if tx
                .send(ActorMessage::GetMtu {
                    respond_to: resp_tx,
                })
                .await
                .is_ok()
            {
                return resp_rx.await.unwrap_or(1200);
            }
        }
        1200
    }

    /// Sends data on a stream within a connection.
    pub async fn send(&self, cid: &[u8], stream_id: u32, data: &[u8]) -> Result<()> {
        if let Some(tx) = self.routing_table.get(cid) {
            let (resp_tx, resp_rx) = oneshot::channel();
            tx.send(ActorMessage::OutgoingData {
                stream_id,
                data: Bytes::copy_from_slice(data),
                respond_to: resp_tx,
            })
            .await
            .map_err(|e| ZtError::Io(std::io::Error::other(format!("Actor send failed: {}", e))))?;
            return resp_rx.await.unwrap_or(Err(ZtError::ActorFailed));
        }
        Err(ZtError::ActorFailed)
    }

    /// Sends an unreliable datagram on a connection.
    pub async fn send_datagram(&self, cid: &[u8], data: Bytes) -> Result<()> {
        if let Some(tx) = self.routing_table.get(cid) {
            let (resp_tx, resp_rx) = oneshot::channel();
            tx.send(ActorMessage::SendDatagram {
                data,
                respond_to: resp_tx,
            })
            .await
            .map_err(|e| ZtError::Io(std::io::Error::other(format!("Actor send failed: {}", e))))?;
            return resp_rx.await.unwrap_or(Err(ZtError::ActorFailed));
        }
        Err(ZtError::ActorFailed)
    }

    /// Closes a specific stream within a connection.
    pub async fn close_stream(&self, cid: &[u8], stream_id: u32) -> Result<()> {
        if let Some(tx) = self.routing_table.get(cid) {
            let _ = tx.send(ActorMessage::CloseStream { stream_id }).await;
        }
        Ok(())
    }

    /// Opens a new stream on an existing connection.
    pub async fn open_stream(&self, cid: &[u8]) -> Result<ZtStream> {
        self.open_stream_with_type(cid, crate::transport::state::StreamType::Bidirectional).await
    }

    /// Opens a new stream of a specific type on an existing connection.
    pub async fn open_stream_with_type(&self, cid: &[u8], stream_type: crate::transport::state::StreamType) -> Result<ZtStream> {
        if let Some(tx) = self.routing_table.get(cid) {
            let (resp_tx, resp_rx) = oneshot::channel();
            tx.send(ActorMessage::OpenStream {
                stream_type,
                respond_to: resp_tx,
            })
            .await
            .map_err(|_| ZtError::ActorFailed)?;
            let stream = resp_rx.await.unwrap_or(Err(ZtError::ActorFailed))?;
            return Ok(stream);
        }
        Err(ZtError::ActorFailed)
    }

    /// Closes a connection entirely.
    pub async fn close(&self, cid: &[u8]) -> Result<()> {
        if let Some((_, tx)) = self.routing_table.remove(cid) {
            let _ = tx.send(ActorMessage::Close).await;
        }
        Ok(())
    }

    /// Accepts an incoming connection.
    pub async fn accept(&self) -> Option<ZtConnectionHandle> {
        let mut rx = self.incoming_rx.lock().await;
        rx.recv().await
    }

    /// Returns the local socket address this endpoint is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }

    /// Connect to a remote peer. Blocks until the handshake completes.
    pub async fn connect(self: &Arc<Self>, addr: SocketAddr) -> Result<ZtConnectionHandle> {
        let mut scid = vec![0u8; 8];
        let mut dcid = vec![0u8; 8];
        rand::thread_rng().fill(&mut scid[..]);
        rand::thread_rng().fill(&mut dcid[..]);

        let mut conn = ZtConnection::new_with_cc(addr, scid.clone(), dcid.clone(), self.cc_algo);
        conn.state = ConnectionState::Handshaking;

        let (actor_tx, actor_rx) = mpsc::channel(1024);
        let (stream_tx, stream_rx) = mpsc::channel(128);
        let (datagram_tx, datagram_rx) = mpsc::channel(1024);

        let (wait_tx, wait_rx) = oneshot::channel();

        let (ephemeral_secret, ephemeral_public) = crate::crypto::keypair::generate_keypair();
        
        let mut csprng = rand::rngs::OsRng;
        let client_ed_signing_key = SigningKey::generate(&mut csprng);
        let client_ed_public_key = client_ed_signing_key.verifying_key();

        let actor = ZtConnectionActor::new(
            self.clone(),
            self.socket.clone(),
            actor_rx,
            conn,
            ephemeral_public,
            Some(ephemeral_secret),
            Some(client_ed_signing_key),
            client_ed_public_key,
            self.psk,
            Some(wait_tx),
            self.routing_table.clone(),
            scid.clone(),
            stream_tx.clone(),
            datagram_tx,
            true,
            actor_tx.clone(),
        );

        self.routing_table.insert(scid.clone(), actor_tx);
        tokio::spawn(actor.run());

        match tokio::time::timeout(std::time::Duration::from_secs(5), wait_rx).await {
            Ok(Ok(_)) => {
                Ok(ZtConnectionHandle::new(self.clone(), scid, stream_rx, datagram_rx))
            }
            _ => {
                self.routing_table.remove(&scid);
                Err(ZtError::Timeout)
            }
        }
    }
}
