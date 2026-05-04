use super::ZtConnectionActor;
use crate::error::{Result, ZtError};
use crate::protocol::frame::Frame;
use crate::protocol::packet::PacketHeader;
use crate::transport::stream_state::ConnectionState;
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
        if header.version != 1 {
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
        while payload_bytes.remaining() > 0 {
            if let Ok(Frame::Handshake {
                public_key,
                ed_public_key,
                transcript_hash,
                signature,
            }) = Frame::decode(&mut payload_bytes)
            {
                handshake = Some((public_key, ed_public_key, transcript_hash, signature));
            }
        }
        let Some((pk_bytes, remote_ed_pk_bytes, transcript_hash, remote_sig_bytes)) = handshake
        else {
            return Err(ZtError::Crypto("No handshake".into()));
        };

        let old_scid = self.state.dcid.clone();
        let new_dcid = header.scid.clone();
        
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, &self.state.scid);
        sha2::Digest::update(&mut hasher, &old_scid);
        sha2::Digest::update(&mut hasher, self.public_key.as_bytes());
        if let Some(ref c) = self.state.cookie {
            sha2::Digest::update(&mut hasher, c);
        }
        sha2::Digest::update(&mut hasher, &new_dcid);
        sha2::Digest::update(&mut hasher, pk_bytes);
        let expected_hash = sha2::Digest::finalize(hasher).to_vec();

        if expected_hash != transcript_hash {
            return Err(ZtError::Crypto("Invalid Transcript Hash".into()));
        }

        let remote_ed_pk = VerifyingKey::from_bytes(&remote_ed_pk_bytes)
            .map_err(|_| ZtError::Crypto("Invalid EdPK".into()))?;
        remote_ed_pk
            .verify(&expected_hash, &Signature::from_bytes(&remote_sig_bytes))
            .map_err(|_| ZtError::Crypto("Invalid Sig".into()))?;
        let shared = crate::crypto::keypair::compute_shared_secret(
            &self.static_secret,
            PublicKey::from(pk_bytes),
        );
        self.state.dcid = new_dcid.clone();
        self.state.crypto = Some(crate::crypto::CryptoContext::from_shared_secret(
            shared,
            &self.state.scid,
            &self.state.dcid,
            self.psk,
            true,
        ));
        self.state.addr = addr;
        self.state.state = ConnectionState::Active;
        self.state.mark_processed(header.packet_number);
        if old_scid != new_dcid {
            self.routing_table.remove(&old_scid);
            if let Some(actor_tx) = self.routing_table.get(&self.scid) {
                self.routing_table.insert(new_dcid, actor_tx.clone());
            }
        }
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
