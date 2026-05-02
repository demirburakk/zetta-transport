use crate::error::{Result, ZtError};
use crate::stream::{ZtConnectionHandle, ZtStream};
use crate::transport::actor::{ActorMessage, ZtConnectionActor};
use crate::transport::connection::ZtConnection;
use crate::transport::stream_state::{ConnectionState, StreamState};
use bytes::Bytes;
use dashmap::DashMap;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::Rng;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, Notify, Semaphore, mpsc, oneshot};

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

    incoming_rx: Mutex<mpsc::Receiver<ZtConnectionHandle>>,
    pub(crate) incoming_tx: mpsc::Sender<ZtConnectionHandle>,
}

impl ZtEndpoint {
    /// Binds an endpoint to the given local address.
    pub async fn bind(addr: &str, psk: Option<[u8; 32]>) -> Result<Arc<Self>> {
        let mut csprng = rand::rngs::OsRng;
        let ed_signing_key = SigningKey::generate(&mut csprng);
        let ed_public_key = ed_signing_key.verifying_key();

        let socket = Arc::new(UdpSocket::bind(addr).await?);
        let (tx, rx) = mpsc::channel(1024);
        let cookie_key = rand::thread_rng().r#gen::<[u8; 32]>();

        let endpoint = Arc::new(Self {
            socket,
            routing_table: Arc::new(DashMap::new()),
            ed_signing_key,
            ed_public_key,
            psk,
            cookie_key,
            verify_peer_key: None,
            handshake_semaphore: Arc::new(Semaphore::new(256)),
            incoming_rx: Mutex::new(rx),
            incoming_tx: tx,
        });

        Self::start_router(endpoint.clone());
        Ok(endpoint)
    }

    /// Starts the packet router task that dispatches incoming datagrams
    /// to the correct per-connection actor or initiates new handshakes.
    fn start_router(endpoint: Arc<Self>) {
        tokio::spawn(async move {
            let mut buf = bytes::BytesMut::zeroed(2048);
            loop {
                if let Ok((len, addr)) = endpoint.socket.recv_from(&mut buf).await {
                    let data = buf.split_to(len);
                    if buf.capacity() < 2048 {
                        buf = bytes::BytesMut::zeroed(2048);
                    } else {
                        // Restore zeroed size for recv_from
                        buf.resize(2048, 0);
                    }

                    if let Some(dcid) = crate::protocol::routing::extract_dcid_fast(&data) {
                        if let Some(tx) = endpoint.routing_table.get(&dcid) {
                            if let Err(_e) =
                                tx.try_send(ActorMessage::IncomingPacket { data, addr })
                            {
                                tracing::trace!("Dropped packet for {:?}: queue full", dcid);
                            }
                        } else {
                            let ep_clone = endpoint.clone();
                            tokio::spawn(async move {
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
                        }
                    }
                }
            }
        });
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

    /// Closes a specific stream within a connection.
    pub async fn close_stream(&self, cid: &[u8], stream_id: u32) -> Result<()> {
        if let Some(tx) = self.routing_table.get(cid) {
            let _ = tx.send(ActorMessage::CloseStream { stream_id }).await;
        }
        Ok(())
    }

    /// Opens a new stream on an existing connection.
    pub async fn open_stream(&self, cid: &[u8]) -> Result<ZtStream> {
        if let Some(tx) = self.routing_table.get(cid) {
            let (resp_tx, resp_rx) = oneshot::channel();
            tx.send(ActorMessage::OpenStream {
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
    ///
    /// This method holds the `Mutex` lock for the lifetime of the `recv()`
    /// call (i.e. until a connection arrives). Calling `accept()` from
    /// multiple tasks is safe and sequential.
    pub async fn accept(&self) -> Option<ZtConnectionHandle> {
        let mut rx = self.incoming_rx.lock().await;
        rx.recv().await
    }

    /// Returns the local socket address this endpoint is bound to.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.socket.local_addr()?)
    }

    /// Initiates a connection to a remote peer.
    pub async fn connect(self: &Arc<Self>, addr: SocketAddr) -> Result<ZtConnectionHandle> {
        let mut scid = vec![0u8; 8];
        rand::thread_rng().fill(&mut scid[..]);
        let mut dcid = vec![0u8; 8];
        rand::thread_rng().fill(&mut dcid[..]);

        let mut conn = ZtConnection::new(addr, scid.clone(), dcid);
        conn.bytes_received = 1000000; // Client is not subject to amplification limits
        conn.state = ConnectionState::Handshaking;

        let (data_tx, data_rx) = mpsc::channel(2048);
        let window_opened = Arc::new(Notify::new());
        conn.streams
            .insert(0, StreamState::new(data_tx, window_opened.clone()));

        let (actor_tx, actor_rx) = mpsc::channel(1024);
        let (stream_tx, stream_rx) = mpsc::channel(128);

        let (wait_tx, wait_rx) = oneshot::channel();

        let (ephemeral_secret, ephemeral_public) = crate::crypto::keypair::generate_keypair();

        let actor = ZtConnectionActor::new(
            self.clone(),
            self.socket.clone(),
            actor_rx,
            conn,
            ephemeral_public,
            ephemeral_secret,
            self.ed_signing_key.clone(),
            self.ed_public_key,
            self.psk,
            Some(wait_tx),
            self.routing_table.clone(),
            scid.clone(),
            stream_tx.clone(),
            true,
        );

        self.routing_table.insert(scid.clone(), actor_tx);
        tokio::spawn(actor.run());

        match tokio::time::timeout(std::time::Duration::from_secs(5), wait_rx).await {
            Ok(Ok(_)) => {
                let stream0 = ZtStream::new(self.clone(), scid.clone(), 0, data_rx, window_opened);
                let _ = stream_tx.try_send(stream0);
                Ok(ZtConnectionHandle::new(self.clone(), scid, stream_rx))
            }
            _ => {
                self.routing_table.remove(&scid);
                Err(ZtError::Timeout)
            }
        }
    }
}
