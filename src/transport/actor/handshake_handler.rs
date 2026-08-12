use super::ZtConnectionActor;
use crate::error::{Result, ZtError};
use crate::protocol::PROTOCOL_VERSION;
use crate::protocol::frame::{Frame, TransportParameters};
use crate::protocol::packet::PacketHeader;
use crate::transport::state::ConnectionState;
use bytes::{Buf, Bytes};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::Digest;
use std::net::SocketAddr;
use x25519_dalek::PublicKey;

impl ZtConnectionActor {
    pub(super) fn handle_handshake_response(
        &mut self,
        header: PacketHeader,
        mut payload: Bytes,
        aad: &[u8],
        addr: SocketAddr,
    ) -> Result<()> {
        if header.version != PROTOCOL_VERSION {
            return Err(ZtError::InvalidPacket("Unsupported version".into()));
        }
        let crypto = crate::crypto::CryptoContext::initial(&header.dcid, true);
        if payload.len() < 16 {
            return Ok(());
        }
        let tag = payload.split_off(payload.len() - 16);
        let mut payload_mut = payload.to_vec();
        let tag_array: [u8; 16] = tag[..16]
            .try_into()
            .map_err(|_| ZtError::Crypto("Invalid tag length".into()))?;
        crypto.decrypt_in_place(
            header.packet_number,
            aad,
            &mut payload_mut,
            &tag_array,
            false,
        )?;
        let mut payload_bytes = Bytes::from(payload_mut);
        let mut handshake = None;
        let mut remote_parameters: Option<TransportParameters> = None;
        while payload_bytes.remaining() > 0 {
            match Frame::decode(&mut payload_bytes)? {
                Frame::Handshake {
                    public_key,
                    ed_public_key,
                    transcript_hash,
                    signature,
                    alpn,
                } => {
                    handshake = Some((public_key, ed_public_key, transcript_hash, signature, alpn));
                }
                Frame::TransportParameters(parameters) => {
                    if remote_parameters.is_some() {
                        return Err(ZtError::InvalidPacket(
                            "duplicate transport parameters".into(),
                        ));
                    }
                    remote_parameters = Some(parameters.validate()?);
                }
                _ => {}
            }
        }
        let Some((pk_bytes, remote_ed_pk_bytes, transcript_hash, remote_sig_bytes, remote_alpn)) =
            handshake
        else {
            return Err(ZtError::Crypto("No handshake".into()));
        };
        let remote_parameters = remote_parameters
            .ok_or_else(|| ZtError::InvalidPacket("No transport parameters in Handshake".into()))?;

        let expected_alpn = self.endpoint.alpn.read().unwrap().clone();
        if remote_alpn != expected_alpn {
            return Err(ZtError::Crypto("ALPN negotiation failed".into()));
        }

        let old_scid = self.state.dcid.clone();
        let new_dcid = header.scid.clone();

        // Build transcript hash including protocol version to prevent downgrade attacks.
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, PROTOCOL_VERSION.to_be_bytes());
        sha2::Digest::update(&mut hasher, &self.state.scid);
        sha2::Digest::update(&mut hasher, &old_scid);
        sha2::Digest::update(&mut hasher, self.public_key.as_bytes());
        if let Some(ref c) = self.state.cookie {
            sha2::Digest::update(&mut hasher, c);
        }
        let local_parameters = TransportParameters::from_config(&self.endpoint.config);
        sha2::Digest::update(&mut hasher, local_parameters.transcript_bytes());
        sha2::Digest::update(&mut hasher, &new_dcid);
        sha2::Digest::update(&mut hasher, pk_bytes);
        sha2::Digest::update(&mut hasher, remote_parameters.transcript_bytes());
        let expected_hash = sha2::Digest::finalize(hasher).to_vec();

        if expected_hash != transcript_hash {
            return Err(ZtError::Crypto("Invalid Transcript Hash".into()));
        }

        let remote_ed_pk = VerifyingKey::from_bytes(&remote_ed_pk_bytes)
            .map_err(|_| ZtError::Crypto("Invalid EdPK".into()))?;
        remote_ed_pk
            .verify(&expected_hash, &Signature::from_bytes(&remote_sig_bytes))
            .map_err(|_| ZtError::Crypto("Invalid Sig".into()))?;

        if !self.endpoint.verify_peer_key(&remote_ed_pk_bytes) {
            return Err(ZtError::Unauthorized);
        }

        // Consume the ephemeral secret — it is moved into diffie_hellman and
        // destroyed, enforcing forward secrecy at the type level.
        let ephemeral_secret = self
            .ephemeral_secret
            .take()
            .ok_or_else(|| ZtError::Crypto("Ephemeral secret already consumed".into()))?;

        let shared = crate::crypto::keypair::compute_shared_secret(
            ephemeral_secret,
            PublicKey::from(pk_bytes),
        );
        self.state.dcid = new_dcid.clone();
        self.state.crypto = Some(Box::new(crate::crypto::CryptoContext::from_shared_secret(
            shared,
            &self.state.scid,
            &self.state.dcid,
            self.psk,
            true,
        )));
        self.state.addr = addr;
        self.state.peer_max_streams = remote_parameters.max_streams;
        self.state.peer_initial_stream_window = remote_parameters.initial_stream_window;
        self.state.remote_window = remote_parameters.initial_max_data;
        self.state.peer_max_datagram_size = remote_parameters.max_datagram_size as usize;
        self.state.idle_timeout =
            self.endpoint
                .config
                .idle_timeout
                .min(std::time::Duration::from_millis(
                    remote_parameters.idle_timeout_ms,
                ));
        self.state.state = ConnectionState::Active;
        self.state.mark_processed(header.packet_number);
        // Handshake complete: clear the Initial packet from unacked_packets
        self.state.unacked_packets.clear();
        self.state.bytes_in_flight = 0;
        if let Some(tx) = self.handshake_waiter.take() {
            let _ = tx.send(());
        }
        Ok(())
    }

    pub(super) fn handle_retry_packet(
        &mut self,
        _header: PacketHeader,
        payload: Bytes,
        _addr: SocketAddr,
    ) -> Result<()> {
        self.send_initial_packet(Some(payload))
    }
}
