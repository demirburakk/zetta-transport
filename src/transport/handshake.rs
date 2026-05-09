use crate::crypto::CryptoContext;
use crate::error::{Result, ZtError};
use crate::protocol::frame::Frame;
use crate::protocol::packet::{PacketHeader, PacketType};
use crate::stream::{ZtConnectionHandle, ZtStream};
use crate::transport::actor::ZtConnectionActor;
use crate::transport::connection::ZtConnection;
use crate::transport::cookie;
use crate::transport::endpoint::ZtEndpoint;
use crate::transport::state::{ConnectionState, StreamState};
use bytes::{Buf, Bytes, BytesMut};
use ed25519_dalek::{Signature, Signer, Verifier, VerifyingKey};
use rand::Rng;
use sha2::Digest;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{Notify, mpsc};
use x25519_dalek::PublicKey;

/// Current protocol version constant used in transcript binding.
const PROTOCOL_VERSION: u32 = 1;

/// Server-side handshake processing.
///
/// Handles incoming Initial packets: validates the anti-amplification minimum,
/// verifies the retry cookie, authenticates the peer's Ed25519 signature,
/// performs the X25519 key exchange, and creates the connection actor.
pub(crate) async fn handle_handshake(
    endpoint: Arc<ZtEndpoint>,
    data: Bytes,
    addr: SocketAddr,
) -> Result<()> {
    // Semaphore acquisition is now handled upstream in `endpoint.rs` before `tokio::spawn`.
    if data.len() < 1200 {
        return Ok(()); // Anti-amplification drop
    }

    let mut mutable_packet = data.to_vec();
    // Remove Header Protection from the incoming Initial packet
    if let Some(offset) = PacketHeader::get_pn_offset(&mutable_packet) {
        let dcid_opt = crate::protocol::routing::extract_dcid_fast(&mutable_packet);
        if let Some(dcid) = dcid_opt {
            let crypto = CryptoContext::initial(&dcid, false);
            crypto.remove_header_protection(&mut mutable_packet, offset, false)?;
        }
    }
    let original_data = Bytes::from(mutable_packet);
    let mut data_cursor = original_data.clone();
    let initial_len = data_cursor.remaining();

    let header = match PacketHeader::decode(&mut data_cursor) {
        Ok(h) => h,
        Err(e) => {
            tracing::debug!("Failed to decode packet header in handshake: {:?}", e);
            return Ok(());
        }
    };
    let header_len = initial_len - data_cursor.remaining();
    let aad = &original_data[..header_len];

    if !header.is_long || header.p_type != PacketType::Initial {
        return Ok(());
    }
    if header.version != PROTOCOL_VERSION {
        return Ok(());
    }

    let mut payload = data_cursor.to_vec();
    if payload.len() < 16 {
        return Ok(());
    }
    let tag_bytes = payload.split_off(payload.len() - 16);
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&tag_bytes);

    let crypto = CryptoContext::initial(&header.dcid, false);
    if let Err(e) = crypto.decrypt_in_place(header.packet_number, aad, &mut payload, &tag, false) {
        tracing::debug!("Handshake decryption failed: {:?}", e);
        return Ok(());
    }

    let mut payload_bytes = Bytes::from(payload);
    let mut pk_bytes = [0u8; 32];
    let mut remote_ed_pk_bytes = [0u8; 32];
    let mut remote_sig_bytes = [0u8; 64];
    let mut remote_transcript_hash = Vec::new();

    let mut cookie_data: Option<Bytes> = None;
    let mut handshake_found = false;

    while payload_bytes.remaining() > 0 {
        match Frame::decode(&mut payload_bytes) {
            Ok(Frame::Handshake {
                public_key,
                ed_public_key,
                transcript_hash,
                signature,
            }) => {
                pk_bytes = public_key;
                remote_ed_pk_bytes = ed_public_key;
                remote_transcript_hash = transcript_hash;
                remote_sig_bytes = signature;
                handshake_found = true;
            }
            Ok(Frame::Cookie { cookie: c }) => {
                cookie_data = Some(c);
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }

    if !handshake_found {
        return Err(ZtError::InvalidPacket(
            "No handshake frame in Initial".into(),
        ));
    }

    let current_time = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let is_cookie_valid = cookie_data.as_deref().is_some_and(|c| {
        cookie::verify_retry_cookie(&endpoint.cookie_key, &addr, &header.scid, c, current_time)
    });

    if !is_cookie_valid {
        let new_cookie =
            cookie::make_retry_cookie(&endpoint.cookie_key, &addr, &header.scid, current_time);
        send_retry(
            &endpoint,
            addr,
            &header.scid,
            header.packet_number,
            &new_cookie,
        )?;
        return Ok(());
    }

    {
        // Verify Ed25519 signature
        let remote_ed_pk = VerifyingKey::from_bytes(&remote_ed_pk_bytes)
            .map_err(|_| ZtError::Crypto("Invalid Ed25519 Public Key".into()))?;
        let remote_sig = Signature::from_bytes(&remote_sig_bytes);

        // Client transcript includes protocol version to prevent downgrade attacks.
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, &PROTOCOL_VERSION.to_be_bytes());
        sha2::Digest::update(&mut hasher, &header.scid);
        sha2::Digest::update(&mut hasher, &header.dcid);
        sha2::Digest::update(&mut hasher, pk_bytes);
        if let Some(ref c) = cookie_data {
            sha2::Digest::update(&mut hasher, c);
        }
        let expected_hash = sha2::Digest::finalize(hasher).to_vec();

        if expected_hash != remote_transcript_hash {
            return Err(ZtError::Crypto("Invalid Transcript Hash".into()));
        }

        remote_ed_pk
            .verify(&expected_hash, &remote_sig)
            .map_err(|_| ZtError::Crypto("Invalid Handshake Signature".into()))?;

        if let Some(verifier) = &endpoint.verify_peer_key
            && !verifier(&remote_ed_pk_bytes)
        {
            return Err(ZtError::Unauthorized);
        }

        // Generate an ephemeral keypair. The secret is consumed by
        // compute_shared_secret and immediately dropped — true PFS.
        let (ephemeral_secret, ephemeral_public) = crate::crypto::keypair::generate_keypair();
        let shared = crate::crypto::keypair::compute_shared_secret(
            ephemeral_secret,
            PublicKey::from(pk_bytes),
        );

        let mut scid = vec![0u8; 8];
        let mut found = false;
        for _ in 0..10 {
            rand::thread_rng().fill(&mut scid[..]);
            if !endpoint.routing_table.contains_key(&scid) {
                found = true;
                break;
            }
        }
        if !found {
            return Err(ZtError::ConnectionIdExhausted);
        }

        let mut new_conn = ZtConnection::new(addr, scid.clone(), header.scid.clone());
        new_conn.bytes_received = original_data.len();

        let (data_tx, data_rx) = mpsc::channel(2048);
        let window_opened = Arc::new(Notify::new());
        new_conn
            .streams
            .insert(0, StreamState::new(data_tx, window_opened.clone()));

        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, &PROTOCOL_VERSION.to_be_bytes());
        sha2::Digest::update(&mut hasher, &header.scid);
        sha2::Digest::update(&mut hasher, &header.dcid);
        sha2::Digest::update(&mut hasher, pk_bytes);
        if let Some(ref c) = cookie_data {
            sha2::Digest::update(&mut hasher, c);
        }
        sha2::Digest::update(&mut hasher, &scid);
        sha2::Digest::update(&mut hasher, ephemeral_public.as_bytes());
        let transcript_hash = sha2::Digest::finalize(hasher).to_vec();

        let hs_payload = crate::transport::state::UnackedPayload::Handshake {
            public_key: *ephemeral_public.as_bytes(),
            ed_public_key: *endpoint.ed_public_key.as_bytes(),
            transcript_hash: transcript_hash.clone(),
            signature: endpoint.ed_signing_key.sign(&transcript_hash).to_bytes(),
        };
        new_conn.unpaced_queue.push_back(hs_payload);

        new_conn.mark_processed(header.packet_number);
        new_conn.state = ConnectionState::Active;

        new_conn.crypto = Some(CryptoContext::from_shared_secret(
            shared,
            &new_conn.scid,
            &new_conn.dcid,
            endpoint.psk,
            false,
        ));

        let (actor_tx, actor_rx) = mpsc::channel(1024);
        let (stream_tx, stream_rx) = mpsc::channel(128);
        let conn_closed = new_conn.closed.clone();

        // Server-side actor does not need the ephemeral secret (already consumed).
        // It is passed as None to eliminate the need for a dummy keypair.
        let server_actor_pk = PublicKey::from(*endpoint.ed_public_key.as_bytes());

        let actor = ZtConnectionActor::new(
            endpoint.clone(),
            endpoint.socket.clone(),
            actor_rx,
            new_conn,
            server_actor_pk,
            None,
            endpoint.ed_signing_key.clone(),
            endpoint.ed_public_key,
            endpoint.psk,
            None,
            endpoint.routing_table.clone(),
            scid.clone(),
            stream_tx.clone(),
            false,
        );

        endpoint.routing_table.insert(scid.clone(), actor_tx);

        struct RoutingTableGuard {
            table: Arc<dashmap::DashMap<Vec<u8>, mpsc::Sender<crate::transport::actor::ActorMessage>>>,
            scid: Vec<u8>,
            commit: bool,
        }
        impl Drop for RoutingTableGuard {
            fn drop(&mut self) {
                if !self.commit {
                    self.table.remove(&self.scid);
                }
            }
        }
        let mut cleanup_guard = RoutingTableGuard {
            table: endpoint.routing_table.clone(),
            scid: scid.clone(),
            commit: false,
        };

        tokio::spawn(actor.run());

        let conn_handle = ZtConnectionHandle::new(endpoint.clone(), scid.clone(), stream_rx);
        let stream0 = ZtStream::new(endpoint.clone(), scid.clone(), 0, data_rx, window_opened, conn_closed);
        if stream_tx.try_send(stream0).is_err() {
            tracing::warn!("Stream 0 channel full; dropping preallocated stream");
        }

        if endpoint.incoming_tx.try_send(conn_handle).is_err() {
            tracing::warn!(
                "Server accept queue is full. Dropping incoming connection from {:?}",
                addr
            );
            return Ok(()); // cleanup_guard will remove it from routing_table
        }

        cleanup_guard.commit = true;
    }
    Ok(())
}

/// Sends a Retry packet with the HMAC-authenticated cookie.
///
/// Retry packets carry a plaintext token and have no encrypted payload,
/// so header protection is not applied.
fn send_retry(
    endpoint: &Arc<ZtEndpoint>,
    addr: SocketAddr,
    client_scid: &[u8],
    pn: u64,
    cookie_bytes: &[u8; 40],
) -> Result<()> {
    let retry_header = PacketHeader {
        p_type: PacketType::Retry,
        is_long: true,
        version: PROTOCOL_VERSION,
        dcid: client_scid.to_vec(),
        scid: Vec::new(),
        packet_number: pn,
        key_phase: false,
        pn_len: 1,
    };

    let mut buf = BytesMut::with_capacity(128);
    retry_header.encode(&mut buf);
    buf.extend_from_slice(cookie_bytes);

    if let Err(e) = endpoint.socket.try_send_to(&buf, addr) {
        tracing::debug!("Failed to send retry: {}", e);
    }
    Ok(())
}
