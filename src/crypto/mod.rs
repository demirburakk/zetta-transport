use crate::error::{Result, ZtError};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

/// Manages encryption and decryption of packet payloads using AEAD.
/// It uses a SHA-256 KDF to derive the actual encryption key from a Diffie-Hellman shared secret.
pub struct CryptoContext {
    tx_cipher: ChaCha20Poly1305,
    rx_cipher: ChaCha20Poly1305,
}

impl CryptoContext {
    /// Creates a new encryption context from a derived shared secret (32 bytes).
    /// Uses SCID and DCID to derive unique Tx and Rx keys to prevent two-time pad attacks.
    /// If a Pre-Shared Key (PSK) is provided, it is mixed into the KDF to authenticate the endpoints.
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
        let tx_key = hasher.clone().finalize();

        let mut hasher2 = Sha256::new();
        hasher2.update(shared_secret);
        hasher2.update(peer_dcid);
        if let Some(key) = psk {
            hasher2.update(key);
        }
        let rx_key = hasher2.finalize();

        Self {
            tx_cipher: ChaCha20Poly1305::new(tx_key.as_slice().into()),
            rx_cipher: ChaCha20Poly1305::new(rx_key.as_slice().into()),
        }
    }

    /// Generates a new X25519 keypair for Diffie-Hellman key exchange.
    pub fn generate_keypair() -> (StaticSecret, PublicKey) {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        (secret, public)
    }

    /// Computes a shared secret using own secret and peer's public key.
    pub fn compute_shared_secret(my_secret: StaticSecret, their_public: PublicKey) -> [u8; 32] {
        my_secret.diffie_hellman(&their_public).to_bytes()
    }

    /// Encrypts plaintext with additional associated data (AAD).
    /// Uses the packet number to generate a unique nonce for each operation.
    pub fn encrypt(
        &self,
        packet_number: u64,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        let nonce = self.generate_nonce(packet_number);
        let payload = Payload {
            msg: plaintext,
            aad: associated_data,
        };

        self.tx_cipher
            .encrypt(&nonce, payload)
            .map_err(|e| ZtError::Crypto(format!("Encryption failed: {}", e)))
    }

    /// Decrypts ciphertext and validates integrity using AAD.
    pub fn decrypt(
        &self,
        packet_number: u64,
        ciphertext: &[u8],
        associated_data: &[u8],
    ) -> Result<Vec<u8>> {
        let nonce = self.generate_nonce(packet_number);
        let payload = Payload {
            msg: ciphertext,
            aad: associated_data,
        };

        self.rx_cipher
            .decrypt(&nonce, payload)
            .map_err(|e| ZtError::Crypto(format!("Decryption failed: {}", e)))
    }

    /// Generates a unique 96-bit nonce based on the monotonically increasing packet number.
    fn generate_nonce(&self, packet_number: u64) -> Nonce {
        let mut nonce_bytes = [0u8; 12];
        // 4 bytes zero padding + 8 bytes packet number (Big Endian)
        nonce_bytes[4..12].copy_from_slice(&packet_number.to_be_bytes());
        *Nonce::from_slice(&nonce_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_handshake_and_exchange() {
        let (alice_sec, alice_pub) = CryptoContext::generate_keypair();
        let (bob_sec, bob_pub) = CryptoContext::generate_keypair();

        let alice_shared = CryptoContext::compute_shared_secret(alice_sec, bob_pub);
        let bob_shared = CryptoContext::compute_shared_secret(bob_sec, alice_pub);

        assert_eq!(alice_shared, bob_shared);

        let scid = b"ALICE_ID";
        let dcid = b"BOB_ID__";

        let alice_ctx = CryptoContext::from_shared_secret(alice_shared, scid, dcid, None);
        let bob_ctx = CryptoContext::from_shared_secret(bob_shared, dcid, scid, None); // Note the reversed IDs

        let plaintext = b"Hello, Bob! This is Alice.";
        let aad = b"PacketHeader123";

        let ciphertext = alice_ctx.encrypt(1, plaintext, aad).unwrap();

        // Bob should be able to decrypt
        let decrypted = bob_ctx.decrypt(1, &ciphertext, aad).unwrap();
        assert_eq!(plaintext, &decrypted[..]);

        // Decryption with wrong AAD should fail
        assert!(bob_ctx.decrypt(1, &ciphertext, b"WrongHeader").is_err());

        // Decryption with wrong packet number should fail
        assert!(bob_ctx.decrypt(2, &ciphertext, aad).is_err());

        // Alice cannot decrypt her own message (Tx and Rx keys are different)
        assert!(alice_ctx.decrypt(1, &ciphertext, aad).is_err());
    }
}
