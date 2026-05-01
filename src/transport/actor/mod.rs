mod event_loop;
mod handshake_handler;
mod incoming_handler;
mod packet_sender;

use crate::error::Result;
use crate::stream::ZtStream;
use crate::transport::connection::ZtConnection;
use bytes::Bytes;
use dashmap::DashMap;
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use x25519_dalek::{PublicKey, StaticSecret};

/// Messages exchanged between the endpoint API layer and the per-connection actor.
pub(crate) enum ActorMessage {
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

/// Per-connection actor that owns all mutable connection state and
/// processes messages from the endpoint in a single-threaded event loop.
pub(crate) struct ZtConnectionActor {
    pub(super) endpoint: Arc<crate::transport::endpoint::ZtEndpoint>,
    pub(super) socket: Arc<UdpSocket>,
    pub(super) receiver: mpsc::Receiver<ActorMessage>,
    pub(super) state: ZtConnection,
    pub(super) pending_acks: u32,
    pub(super) public_key: PublicKey,
    pub(super) static_secret: StaticSecret,
    pub(super) ed_signing_key: SigningKey,
    pub(super) ed_public_key: VerifyingKey,
    pub(super) psk: Option<[u8; 32]>,
    pub(super) handshake_waiter: Option<oneshot::Sender<()>>,
    pub(super) routing_table: Arc<DashMap<Vec<u8>, mpsc::Sender<ActorMessage>>>,
    pub(super) scid: Vec<u8>,
    pub(super) last_active_stream_id: u32,
    pub(super) incoming_streams_tx: mpsc::Sender<ZtStream>,
    pub(super) next_stream_id: u32,
}

impl ZtConnectionActor {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        endpoint: Arc<crate::transport::endpoint::ZtEndpoint>,
        socket: Arc<UdpSocket>,
        receiver: mpsc::Receiver<ActorMessage>,
        state: ZtConnection,
        public_key: PublicKey,
        static_secret: StaticSecret,
        ed_signing_key: SigningKey,
        ed_public_key: VerifyingKey,
        psk: Option<[u8; 32]>,
        handshake_waiter: Option<oneshot::Sender<()>>,
        routing_table: Arc<DashMap<Vec<u8>, mpsc::Sender<ActorMessage>>>,
        scid: Vec<u8>,
        incoming_streams_tx: mpsc::Sender<ZtStream>,
    ) -> Self {
        Self {
            endpoint,
            socket,
            receiver,
            state,
            pending_acks: 0,
            public_key,
            static_secret,
            ed_signing_key,
            ed_public_key,
            psk,
            handshake_waiter,
            routing_table,
            scid,
            last_active_stream_id: 0,
            incoming_streams_tx,
            next_stream_id: 1,
        }
    }

    /// Returns the current TX key phase bit for outgoing packets.
    pub(super) fn current_key_phase(&self) -> bool {
        !self.state.current_key_epoch.is_multiple_of(2)
    }
}
