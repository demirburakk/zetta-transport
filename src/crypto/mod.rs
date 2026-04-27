use crate::error::{Result, ZtError};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{AeadInPlace, KeyInit},
};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

pub struct CryptoContext {
    pub tx_key: [u8; 32],
    pub rx_key: [u8; 32],
    tx_cipher: ChaCha20Poly1305,
    rx_cipher: ChaCha20Poly1305,
}

impl CryptoContext {
    pub fn from_shared_secret(
        shared_secret: [u8; 32],
        my_scid: &[u8],
        peer_dcid: &[u8],
        psk: Option<[u8; 32]>,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(shared_secret);
        hasher.update(my_scid);
        if let Some(key) = psk {
            hasher.update(key);
        }
        let mut tx_key = [0u8; 32];
        tx_key.copy_from_slice(&hasher.finalize()[..]);

        let mut hasher2 = Sha256::new();
        hasher2.update(shared_secret);
        hasher2.update(peer_dcid);
        if let Some(key) = psk {
            hasher2.update(key);
        }
        let mut rx_key = [0u8; 32];
        rx_key.copy_from_slice(&hasher2.finalize()[..]);

        Self {
            tx_key,
            rx_key,
            tx_cipher: ChaCha20Poly1305::new(tx_key.as_slice().into()),
            rx_cipher: ChaCha20Poly1305::new(rx_key.as_slice().into()),
        }
    }

    pub fn generate_keypair() -> (StaticSecret, PublicKey) {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        (secret, public)
    }

    pub fn compute_shared_secret(my_secret: StaticSecret, their_public: PublicKey) -> [u8; 32] {
        my_secret.diffie_hellman(&their_public).to_bytes()
    }

    pub fn rotate_keys(&mut self) {
        let mut hasher_tx = Sha256::new();
        hasher_tx.update(&self.tx_key);
        self.tx_key.copy_from_slice(&hasher_tx.finalize()[..]);
        self.tx_cipher = ChaCha20Poly1305::new(self.tx_key.as_slice().into());

        let mut hasher_rx = Sha256::new();
        hasher_rx.update(&self.rx_key);
        self.rx_key.copy_from_slice(&hasher_rx.finalize()[..]);
        self.rx_cipher = ChaCha20Poly1305::new(self.rx_key.as_slice().into());
    }

    pub fn encrypt_in_place(
        &self,
        packet_number: u64,
        aad: &[u8],
        payload: &mut [u8],
    ) -> Result<[u8; 16]> {
        let nonce = self.generate_nonce(packet_number);
        let tag = self.tx_cipher
            .encrypt_in_place_detached(&nonce, aad, payload)
            .map_err(|e| ZtError::Crypto(format!("Encryption failed: {}", e)))?;
        
        let mut tag_bytes = [0u8; 16];
        tag_bytes.copy_from_slice(tag.as_slice());
        Ok(tag_bytes)
    }

    pub fn decrypt_in_place(
        &self,
        packet_number: u64,
        aad: &[u8],
        payload: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<()> {
        let nonce = self.generate_nonce(packet_number);
        let chacha_tag = chacha20poly1305::Tag::from_slice(tag);
        self.rx_cipher
            .decrypt_in_place_detached(&nonce, aad, payload, chacha_tag)
            .map_err(|e| ZtError::Crypto(format!("Decryption failed: {}", e)))
    }

    fn generate_nonce(&self, packet_number: u64) -> Nonce {
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..12].copy_from_slice(&packet_number.to_be_bytes());
        *Nonce::from_slice(&nonce_bytes)
    }
}
