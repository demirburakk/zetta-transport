use crate::error::{Result, ZtError};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{AeadInPlace, KeyInit},
};

use super::header_protection;
use super::key_derivation;

/// Fallback RX keys retained from a previous epoch during key rotation.
struct FallbackRxKeys {
    rx_key: [u8; 32],
    rx_iv: [u8; 12],
    rx_cipher: ChaCha20Poly1305,
}

impl Drop for FallbackRxKeys {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.rx_key.zeroize();
        self.rx_iv.zeroize();
        // ChaCha20Poly1305 does not implement Zeroize on Drop in the chacha20poly1305 crate.
        // The idiomatic safe-Rust workaround is to overwrite the struct with a zero-key instance.
        let zero_key = chacha20poly1305::Key::from([0u8; 32]);
        self.rx_cipher = ChaCha20Poly1305::new(&zero_key);
    }
}

/// Core cryptographic context for a connection.
///
/// Holds the current epoch's keys and ciphers, plus fallback keys for
/// out-of-order packets during key phase rotations.
///
/// We retain exactly ONE level of fallback (`prev_rx`). A two-epoch fallback
/// (`prev_prev`) is not practically reachable because a 1-bit key phase indicator
/// aliases `epoch` and `epoch - 2`, making it impossible to distinguish without
/// an expensive trial-decryption loop.
pub(crate) struct CryptoContext {
    secret: [u8; 32],
    tx_key: [u8; 32],
    rx_key: [u8; 32],
    tx_hp_key: [u8; 32],
    rx_hp_key: [u8; 32],
    tx_iv: [u8; 12],
    rx_iv: [u8; 12],
    tx_cipher: ChaCha20Poly1305,
    rx_cipher: ChaCha20Poly1305,
    pub(crate) epoch: u64,
    is_client: bool,

    // One level of fallback keys for out-of-order packets.
    prev_rx: Option<FallbackRxKeys>,
}

impl Drop for CryptoContext {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret.zeroize();
        self.tx_key.zeroize();
        self.rx_key.zeroize();
        self.tx_hp_key.zeroize();
        self.rx_hp_key.zeroize();
        self.tx_iv.zeroize();
        self.rx_iv.zeroize();
        
        // Overwrite ciphers with zero-key instances to clear key material
        let zero_key = chacha20poly1305::Key::from([0u8; 32]);
        self.tx_cipher = ChaCha20Poly1305::new(&zero_key);
        self.rx_cipher = ChaCha20Poly1305::new(&zero_key);
        // FallbackRxKeys have their own Drop impl
    }
}

impl CryptoContext {
    /// Creates a crypto context from a completed DH shared secret.
    pub(crate) fn from_shared_secret(
        shared_secret: zeroize::Zeroizing<[u8; 32]>,
        my_scid: &[u8],
        peer_dcid: &[u8],
        psk: Option<[u8; 32]>,
        is_client: bool,
    ) -> Self {
        let secret = key_derivation::derive_master_secret(
            &shared_secret,
            my_scid,
            peer_dcid,
            psk,
            is_client,
        );
        let mut ctx = Self::with_secret(secret, is_client);
        ctx.apply_epoch_keys(0);
        ctx
    }

    /// Creates an Initial-packet crypto context.
    ///
    /// Initial keys are deterministic and **not secret** — they provide only
    /// packet authentication (anti-spoofing), not confidentiality. Actual
    /// confidentiality begins after the Handshake phase.
    pub(crate) fn initial(dcid: &[u8], is_client: bool) -> Self {
        let secret = key_derivation::derive_initial_secret(dcid);
        let mut ctx = Self::with_secret(secret, is_client);
        ctx.apply_epoch_keys(0);
        ctx
    }

    /// Creates a zeroed context with the given secret; keys are NOT derived yet.
    fn with_secret(secret: [u8; 32], is_client: bool) -> Self {
        let (tx_hp_key, rx_hp_key) = key_derivation::derive_hp_keys(&secret, is_client);
        Self {
            secret,
            tx_key: [0u8; 32],
            rx_key: [0u8; 32],
            tx_hp_key,
            rx_hp_key,
            tx_iv: [0u8; 12],
            rx_iv: [0u8; 12],
            tx_cipher: ChaCha20Poly1305::new([0u8; 32].as_slice().into()),
            rx_cipher: ChaCha20Poly1305::new([0u8; 32].as_slice().into()),
            epoch: 0,
            is_client,
            prev_rx: None,
        }
    }

    /// Derives and installs keys for the given epoch from `self.secret`.
    fn apply_epoch_keys(&mut self, epoch: u64) {
        self.epoch = epoch;
        let keys = key_derivation::derive_epoch_keys(&self.secret, epoch, self.is_client);
        self.tx_key = keys.tx_key;
        self.rx_key = keys.rx_key;
        self.tx_iv = keys.tx_iv;
        self.rx_iv = keys.rx_iv;
        self.tx_cipher = keys.tx_cipher;
        self.rx_cipher = keys.rx_cipher;
    }

    /// Rotates keys forward: saves current RX keys as prev, ratchets the secret,
    /// and derives new epoch keys. Old prev gets dropped and zeroized automatically.
    pub(crate) fn rotate_keys(&mut self) {
        // Save current RX keys as new prev
        self.prev_rx = Some(FallbackRxKeys {
            rx_key: self.rx_key,
            rx_iv: self.rx_iv,
            rx_cipher: self.rx_cipher.clone(),
        });

        self.secret = key_derivation::ratchet_secret(&mut self.secret);
        self.apply_epoch_keys(self.epoch + 1);
    }

    /// Encrypts payload in-place and returns the 16-byte AEAD tag.
    pub(crate) fn encrypt_in_place(
        &self,
        packet_number: u64,
        aad: &[u8],
        payload: &mut [u8],
    ) -> Result<[u8; 16]> {
        let nonce = self.generate_nonce(packet_number, true, false);
        let tag = self
            .tx_cipher
            .encrypt_in_place_detached(&nonce, aad, payload)
            .map_err(|e| ZtError::Crypto(format!("Encryption failed: {}", e)))?;

        let mut tag_bytes = [0u8; 16];
        tag_bytes.copy_from_slice(tag.as_slice());
        Ok(tag_bytes)
    }

    /// Decrypts payload in-place, verifying the AEAD tag.
    ///
    /// When `use_prev_key` is true, tries the fallback RX key.
    pub(crate) fn decrypt_in_place(
        &self,
        packet_number: u64,
        aad: &[u8],
        payload: &mut [u8],
        tag: &[u8; 16],
        use_prev_key: bool,
    ) -> Result<()> {
        let nonce = self.generate_nonce(packet_number, false, use_prev_key);
        let chacha_tag = chacha20poly1305::Tag::from_slice(tag);

        if use_prev_key {
            if let Some(ref prev) = self.prev_rx {
                let prev_nonce = self.make_nonce_from_iv(&prev.rx_iv, packet_number);
                return prev.rx_cipher
                    .decrypt_in_place_detached(&prev_nonce, aad, payload, chacha_tag)
                    .map_err(|e| ZtError::Crypto(format!("Decryption with prev key failed: {}", e)));
            }
            return Err(ZtError::Crypto("No previous RX cipher available".into()));
        }

        self.rx_cipher
            .decrypt_in_place_detached(&nonce, aad, payload, chacha_tag)
            .map_err(|e| ZtError::Crypto(format!("Decryption failed: {}", e)))
    }

    /// Attempts to decrypt the payload with the NEXT epoch's keys.
    /// If successful, commits the key rotation and returns Ok.
    ///
    /// The temporary ratcheted secret is wrapped in `Zeroizing` to ensure
    /// it is scrubbed from memory whether or not decryption succeeds.
    pub(crate) fn trial_decrypt_and_rotate(
        &mut self,
        packet_number: u64,
        aad: &[u8],
        payload: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<()> {
        use zeroize::Zeroizing;

        let mut secret_clone = self.secret;
        let next_secret = Zeroizing::new(key_derivation::ratchet_secret(&mut secret_clone));
        let next_epoch = self.epoch + 1;
        let keys = key_derivation::derive_epoch_keys(&next_secret, next_epoch, self.is_client);
        
        let nonce = self.make_nonce_from_iv(&keys.rx_iv, packet_number);
        let chacha_tag = chacha20poly1305::Tag::from_slice(tag);
        
        let result = keys.rx_cipher
            .decrypt_in_place_detached(&nonce, aad, payload, chacha_tag)
            .map_err(|e| ZtError::Crypto(format!("Trial decryption failed: {}", e)));

        // Explicitly zeroize before potential early return.
        // (Zeroizing::drop would handle it, but being explicit is clearer.)
        drop(next_secret);

        result?;
            
        // Trial succeeded, commit rotation
        self.rotate_keys();
        Ok(())
    }

    /// Applies header protection to a packet using the TX HP key.
    pub(crate) fn apply_header_protection(
        &self,
        packet: &mut [u8],
        pn_offset: usize,
    ) -> Result<()> {
        header_protection::apply_header_protection(packet, pn_offset, &self.tx_hp_key)
    }

    /// Removes header protection from a received packet in-place using the static RX HP key.
    pub(crate) fn remove_header_protection(
        &self,
        packet: &mut [u8],
        pn_offset: usize,
    ) -> Result<()> {
        header_protection::remove_header_protection(packet, pn_offset, &self.rx_hp_key)
    }

    /// Generates a QUIC-style nonce: IV XOR PacketNumber (right-aligned, big-endian).
    fn generate_nonce(&self, packet_number: u64, is_tx: bool, use_prev_key: bool) -> Nonce {
        let iv = if is_tx {
            &self.tx_iv
        } else if use_prev_key {
            // Default to prev, fallback to current
            self.prev_rx.as_ref().map_or(&self.rx_iv, |p| &p.rx_iv)
        } else {
            &self.rx_iv
        };

        self.make_nonce_from_iv(iv, packet_number)
    }

    /// Constructs a nonce from an arbitrary IV and packet number.
    fn make_nonce_from_iv(&self, iv: &[u8; 12], packet_number: u64) -> Nonce {
        let mut nonce_bytes = [0u8; 12];
        let pn_bytes = packet_number.to_be_bytes();

        nonce_bytes.copy_from_slice(iv);
        for i in 0..8 {
            nonce_bytes[12 - 8 + i] ^= pn_bytes[i];
        }

        *Nonce::from_slice(&nonce_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_context_pair() -> (CryptoContext, CryptoContext) {
        let (secret, public) = crate::crypto::keypair::generate_keypair();
        let (server_secret, server_public) = crate::crypto::keypair::generate_keypair();
        let client_shared = crate::crypto::keypair::compute_shared_secret(secret, server_public);
        let server_shared = crate::crypto::keypair::compute_shared_secret(server_secret, public);

        let client_scid = b"client01";
        let server_scid = b"server01";

        let client =
            CryptoContext::from_shared_secret(client_shared, client_scid, server_scid, None, true);
        let server =
            CryptoContext::from_shared_secret(server_shared, server_scid, client_scid, None, false);
        (client, server)
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let (client, server) = make_context_pair();
        let aad = b"header bytes";
        let plaintext = b"secret message";
        let mut payload = plaintext.to_vec();

        let tag = client.encrypt_in_place(0, aad, &mut payload).unwrap();
        assert_ne!(&payload[..], plaintext);

        server.decrypt_in_place(0, aad, &mut payload, &tag, false).unwrap();
        assert_eq!(&payload[..], plaintext);
    }

    #[test]
    fn different_pn_produces_different_ciphertext() {
        let (client, _) = make_context_pair();
        let aad = b"aad";
        let plaintext = [0u8; 32];

        let mut p1 = plaintext.to_vec();
        let mut p2 = plaintext.to_vec();
        client.encrypt_in_place(0, aad, &mut p1).unwrap();
        client.encrypt_in_place(1, aad, &mut p2).unwrap();
        assert_ne!(p1, p2);
    }

    #[test]
    fn wrong_aad_fails_decryption() {
        let (client, server) = make_context_pair();
        let mut payload = b"data".to_vec();
        let tag = client
            .encrypt_in_place(0, b"correct_aad", &mut payload)
            .unwrap();
        let result = server.decrypt_in_place(0, b"wrong_aad", &mut payload, &tag, false);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_payload_fails_decryption() {
        let (client, server) = make_context_pair();
        let aad = b"aad";
        let mut payload = b"hello".to_vec();
        let tag = client.encrypt_in_place(0, aad, &mut payload).unwrap();
        payload[0] ^= 0xFF;
        let result = server.decrypt_in_place(0, aad, &mut payload, &tag, false);
        assert!(result.is_err());
    }

    #[test]
    fn one_epoch_fallback_works() {
        let (client, mut server) = make_context_pair();
        let aad = b"aad";
        let mut payload = b"old epoch data".to_vec();
        let tag = client.encrypt_in_place(0, aad, &mut payload).unwrap();

        server.rotate_keys();

        server.decrypt_in_place(0, aad, &mut payload, &tag, true).unwrap();
    }

    #[test]
    fn initial_context_symmetric() {
        let dcid = b"test_dcid_01";
        let client_ctx = CryptoContext::initial(dcid, true);
        let server_ctx = CryptoContext::initial(dcid, false);

        let aad = b"initial header";
        let mut payload = b"handshake data".to_vec();
        let tag = client_ctx.encrypt_in_place(0, aad, &mut payload).unwrap();
        server_ctx
            .decrypt_in_place(0, aad, &mut payload, &tag, false)
            .unwrap();
    }
}
