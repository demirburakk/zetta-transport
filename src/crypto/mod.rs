use crate::error::{Result, ZtError};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{AeadInPlace, KeyInit},
};
use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

pub struct CryptoContext {
    master_secret: [u8; 32],
    pub tx_key: [u8; 32],
    pub rx_key: [u8; 32],
    pub tx_hp_key: [u8; 32],
    pub rx_hp_key: [u8; 32],
    tx_iv: [u8; 12],
    rx_iv: [u8; 12],
    tx_cipher: ChaCha20Poly1305,
    rx_cipher: ChaCha20Poly1305,
    epoch: u64,
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
        hasher.update(peer_dcid);
        if let Some(key) = psk {
            hasher.update(key);
        }
        let mut master_secret = [0u8; 32];
        master_secret.copy_from_slice(&hasher.finalize()[..]);

        let mut ctx = Self {
            master_secret,
            tx_key: [0u8; 32],
            rx_key: [0u8; 32],
            tx_hp_key: [0u8; 32],
            rx_hp_key: [0u8; 32],
            tx_iv: [0u8; 12],
            rx_iv: [0u8; 12],
            tx_cipher: ChaCha20Poly1305::new([0u8; 32].as_slice().into()),
            rx_cipher: ChaCha20Poly1305::new([0u8; 32].as_slice().into()),
            epoch: 0,
        };
        ctx.derive_keys(0);
        ctx
    }

    pub fn initial(dcid: &[u8]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"ZettaInitialSalt");
        hasher.update(dcid);
        let mut master_secret = [0u8; 32];
        master_secret.copy_from_slice(&hasher.finalize()[..]);

        let mut ctx = Self {
            master_secret,
            tx_key: [0u8; 32],
            rx_key: [0u8; 32],
            tx_hp_key: [0u8; 32],
            rx_hp_key: [0u8; 32],
            tx_iv: [0u8; 12],
            rx_iv: [0u8; 12],
            tx_cipher: ChaCha20Poly1305::new([0u8; 32].as_slice().into()),
            rx_cipher: ChaCha20Poly1305::new([0u8; 32].as_slice().into()),
            epoch: 0,
        };
        ctx.derive_keys(0);
        ctx
    }

    pub fn generate_keypair() -> (StaticSecret, PublicKey) {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        (secret, public)
    }

    pub fn compute_shared_secret(my_secret: StaticSecret, their_public: PublicKey) -> [u8; 32] {
        my_secret.diffie_hellman(&their_public).to_bytes()
    }

    fn derive_keys(&mut self, epoch: u64) {
        self.epoch = epoch;
        
        let mut hasher_tx = Sha256::new();
        hasher_tx.update(&self.master_secret);
        hasher_tx.update(b"tx_key");
        hasher_tx.update(epoch.to_be_bytes());
        self.tx_key.copy_from_slice(&hasher_tx.finalize()[..]);
        self.tx_cipher = ChaCha20Poly1305::new(self.tx_key.as_slice().into());

        let mut hasher_rx = Sha256::new();
        hasher_rx.update(&self.master_secret);
        hasher_rx.update(b"rx_key");
        hasher_rx.update(epoch.to_be_bytes());
        self.rx_key.copy_from_slice(&hasher_rx.finalize()[..]);
        self.rx_cipher = ChaCha20Poly1305::new(self.rx_key.as_slice().into());

        let mut hasher_tx_hp = Sha256::new();
        hasher_tx_hp.update(&self.master_secret);
        hasher_tx_hp.update(b"tx_hp");
        hasher_tx_hp.update(epoch.to_be_bytes());
        self.tx_hp_key.copy_from_slice(&hasher_tx_hp.finalize()[..]);

        let mut hasher_rx_hp = Sha256::new();
        hasher_rx_hp.update(&self.master_secret);
        hasher_rx_hp.update(b"rx_hp");
        hasher_rx_hp.update(epoch.to_be_bytes());
        self.rx_hp_key.copy_from_slice(&hasher_rx_hp.finalize()[..]);

        let mut hasher_tx_iv = Sha256::new();
        hasher_tx_iv.update(&self.master_secret);
        hasher_tx_iv.update(b"tx_iv");
        hasher_tx_iv.update(epoch.to_be_bytes());
        let tx_iv_hash = hasher_tx_iv.finalize();
        self.tx_iv.copy_from_slice(&tx_iv_hash[..12]);

        let mut hasher_rx_iv = Sha256::new();
        hasher_rx_iv.update(&self.master_secret);
        hasher_rx_iv.update(b"rx_iv");
        hasher_rx_iv.update(epoch.to_be_bytes());
        let rx_iv_hash = hasher_rx_iv.finalize();
        self.rx_iv.copy_from_slice(&rx_iv_hash[..12]);
    }

    pub fn rotate_keys(&mut self) {
        let mut hasher = Sha256::new();
        hasher.update(&self.master_secret);
        hasher.update(b"ratchet");
        self.master_secret.copy_from_slice(&hasher.finalize()[..]);
        self.derive_keys(self.epoch + 1);
    }

    pub fn encrypt_in_place(
        &self,
        packet_number: u64,
        aad: &[u8],
        payload: &mut [u8],
    ) -> Result<[u8; 16]> {
        let nonce = self.generate_nonce(packet_number, true);
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
        let nonce = self.generate_nonce(packet_number, false);
        let chacha_tag = chacha20poly1305::Tag::from_slice(tag);
        self.rx_cipher
            .decrypt_in_place_detached(&nonce, aad, payload, chacha_tag)
            .map_err(|e| ZtError::Crypto(format!("Decryption failed: {}", e)))
    }

    fn generate_nonce(&self, packet_number: u64, is_tx: bool) -> Nonce {
        let iv = if is_tx { &self.tx_iv } else { &self.rx_iv };
        let mut nonce_bytes = [0u8; 12];
        let pn_bytes = packet_number.to_be_bytes();
        for i in 0..12 {
            if i >= 4 {
                nonce_bytes[i] = iv[i] ^ pn_bytes[i - 4];
            } else {
                nonce_bytes[i] = iv[i];
            }
        }
        *Nonce::from_slice(&nonce_bytes)
    }

    pub fn apply_header_protection(&self, packet: &mut [u8], pn_offset: usize) -> Result<()> {
        let sample_offset = pn_offset + 8;
        if sample_offset + 16 > packet.len() {
            return Err(ZtError::InvalidPacket("Packet too short for header protection sample".into()));
        }
        
        let mut counter = [0u8; 4];
        counter.copy_from_slice(&packet[sample_offset..sample_offset + 4]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&packet[sample_offset + 4..sample_offset + 16]);

        // ÇÖZÜM: Karmaşık tür dönüşümlerini bırakıp doğrudan &[u8] dilimlerini kullanıyoruz.
        let mut cipher = ChaCha20::new_from_slices(&self.tx_hp_key, &nonce)
            .map_err(|_| ZtError::Crypto("Invalid HP key or nonce length".into()))?;
        
        let counter_val = u32::from_le_bytes(counter);
        cipher.seek((counter_val as u64) * 64);
        
        let mut mask = [0u8; 9];
        cipher.apply_keystream(&mut mask);
        
        let first_mask = mask[0] & if (packet[0] & 0x80) != 0 { 0x0F } else { 0x1F };
        packet[0] ^= first_mask;
        for i in 0..8 { packet[pn_offset + i] ^= mask[i + 1]; }
        
        Ok(())
    }

    pub fn remove_header_protection(&self, packet: &mut [u8], pn_offset: usize) -> Result<()> {
        let sample_offset = pn_offset + 8;
        if sample_offset + 16 > packet.len() {
            return Err(ZtError::InvalidPacket("Packet too short to resolve header protection".into()));
        }
        
        let mut counter = [0u8; 4];
        counter.copy_from_slice(&packet[sample_offset..sample_offset + 4]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&packet[sample_offset + 4..sample_offset + 16]);

        // ÇÖZÜM: Aynı şekilde rx_hp_key ve nonce dilimlerini doğrudan veriyoruz.
        let mut cipher = ChaCha20::new_from_slices(&self.rx_hp_key, &nonce)
            .map_err(|_| ZtError::Crypto("Invalid HP key or nonce length".into()))?;
        
        let counter_val = u32::from_le_bytes(counter);
        cipher.seek((counter_val as u64) * 64);
        
        let mut mask = [0u8; 9];
        cipher.apply_keystream(&mut mask);
        
        let first_mask = mask[0] & if (packet[0] & 0x80) != 0 { 0x0F } else { 0x1F };
        packet[0] ^= first_mask;
        for i in 0..8 { packet[pn_offset + i] ^= mask[i + 1]; }
        
        Ok(())
    }
}