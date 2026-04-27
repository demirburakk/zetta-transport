use crate::transport::state::{ConnectionState, ZtConnection};
use crate::crypto::CryptoContext;
use crate::error::{Result, ZtError};
use crate::fec::FecEngine;
use crate::protocol::packet::{PacketHeader, PacketType};
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use rand::Rng;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc};
use tokio_util::sync::CancellationToken;
use x25519_dalek::{PublicKey, StaticSecret};

use super::worker;
use super::handler;

const RECV_BUFFER_SIZE: usize = 2048;

#[derive(Debug)]
pub struct ReceivedData {
    pub cid: Vec<u8>,
    pub data: Bytes,
}

pub struct ZtEndpoint {
    pub(crate) socket: Arc<UdpSocket>,
    pub(crate) connections: Arc<DashMap<Vec<u8>, ZtConnection>>,
    pub(crate) chaos_mode: Arc<AtomicBool>,
    pub(crate) static_secret: StaticSecret,
    pub public_key: PublicKey,
    pub psk: Option<[u8; 32]>,
    app_rx: Mutex<mpsc::Receiver<ReceivedData>>,
    pub(crate) app_tx: mpsc::Sender<ReceivedData>,
    pub(crate) shutdown_token: CancellationToken,
}

impl ZtEndpoint {
    pub async fn bind(addr: &str, psk: Option<[u8; 32]>) -> Result<Arc<Self>> {
        let (secret, public) = CryptoContext::generate_keypair();
        let socket = UdpSocket::bind(addr).await?;
        let (tx, rx) = mpsc::channel(RECV_BUFFER_SIZE);
        let shutdown_token = CancellationToken::new();

        let endpoint = Arc::new(Self {
            socket: Arc::new(socket),
            connections: Arc::new(DashMap::new()),
            chaos_mode: Arc::new(AtomicBool::new(false)),
            static_secret: secret,
            public_key: public,
            psk,
            app_rx: Mutex::new(rx),
            app_tx: tx,
            shutdown_token: shutdown_token.clone(),
        });

        worker::spawn_workers(endpoint.clone());

        Ok(endpoint)
    }

    pub async fn get_connection_state(&self, cid: &[u8]) -> Option<(SocketAddr, Vec<u8>, Vec<u8>)> {
        let conns = &self.connections;
        conns
            .get(cid)
            .map(|c| (c.addr, c.scid.clone(), c.dcid.clone()))
    }

    pub async fn resume_connection(&self, addr: SocketAddr, scid: Vec<u8>, dcid: Vec<u8>) {
        let conns = &self.connections;
        let mut conn = ZtConnection::new(addr, scid.clone(), dcid);
        conn.state = ConnectionState::Active;
        conns.insert(scid, conn);
    }

    pub(crate) async fn handle_packet(&self, data: &[u8], addr: SocketAddr) -> Result<()> {
        handler::process_packet(self, data, addr).await
    }

    pub(crate) async fn send_ack_internal(&self, cid: &[u8], pn: u64) -> Result<()> {
        let (addr, local_window, has_crypto) = {
            let conns = &self.connections;
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
            stream_id: 0,
            offset: 0,
        };
        let mut buf = BytesMut::with_capacity(64);
        header.encode(&mut buf);
        let header_bytes = buf.freeze();

        let payload: &[u8] = &[];
        let encrypted = if has_crypto {
            let conns = &self.connections;
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

    pub(crate) async fn send_handshake_internal(&self, cid: &[u8]) -> Result<()> {
        let (addr, scid, dcid, pn, local_window) = {
            let conns = &self.connections;
            let mut c = conns.get_mut(cid).ok_or(ZtError::Unauthorized)?;
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
            stream_id: 0,
            offset: 0,
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
            stream_id: 0,
            offset: 0,
        };

        let mut buf = BytesMut::with_capacity(128);
        header.encode(&mut buf);
        buf.extend_from_slice(self.public_key.as_bytes());

        self.socket.send_to(&buf, remote_addr).await?;

        let conns = &self.connections;
        conns.insert(scid.clone(), conn);
        Ok(scid)
    }

    pub async fn send(&self, cid: &[u8], data: &[u8]) -> Result<()> {
        let (addr, pn, header_bytes, has_crypto) = {
            let conns = &self.connections;
            let mut conn = conns.get_mut(cid).ok_or(ZtError::Unauthorized)?;

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
                stream_id: 0,
                offset: 0,
            };
            let mut buf = BytesMut::with_capacity(64);
            header.encode(&mut buf);
            (conn.addr, pn, buf.freeze(), conn.crypto.is_some())
        };

        let encrypted = if has_crypto {
            let conns = &self.connections;
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
        let conns = &self.connections;
        if let Some(mut conn) = conns.get_mut(cid) {
            conn.unacked_packets
                .insert(pn, (frozen_packet, Instant::now(), 0));
            conn.bytes_in_flight += data.len();
            conn.remote_window -= data.len() as u32;

            if has_crypto {
                conn.sent_shards.push(Bytes::from(encrypted));
                conn.last_fec_shard_added = Some(Instant::now());
                if conn.sent_shards.len() == 4 {
                    let parity = FecEngine::build_parity(&conn.sent_shards);
                    conn.sent_shards.clear();
                    conn.last_fec_shard_added = None;

                    let fec_pn = conn.get_next_packet_number()?;
                    let fec_header = PacketHeader {
                        p_type: PacketType::Fec,
                        is_long: false,
                        version: 0,
                        dcid: conn.dcid.clone(),
                        scid: vec![],
                        packet_number: fec_pn,
                        window_size: conn.local_window,
                        stream_id: 0,
                        offset: 0,
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
            let conns = &self.connections;
            let mut conn = conns.get_mut(cid).ok_or(ZtError::Unauthorized)?;
            let pn = conn.get_next_packet_number()?;
            let header = PacketHeader {
                p_type: PacketType::Close,
                is_long: false,
                version: 0,
                dcid: conn.dcid.clone(),
                scid: vec![],
                packet_number: pn,
                window_size: conn.local_window,
                stream_id: 0,
                offset: 0,
            };
            let mut buf = BytesMut::with_capacity(64);
            header.encode(&mut buf);
            conn.state = ConnectionState::Closed;
            (conn.addr, pn, buf.freeze(), conn.crypto.is_some())
        };

        let payload: &[u8] = &[];
        let encrypted = if has_crypto {
            let conns = &self.connections;
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

        // ZOMBIE PROTECTION: Don't remove immediately. Mark as Closed and let Pruner clean it up later.
        // let conns = &self.connections;
        // conns.remove(cid);

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
