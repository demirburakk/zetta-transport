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
    pub epoch: u64,
    is_client: bool,

    // Fallback keys for out-of-order packets during key phase rotations
    prev_rx_key: Option<[u8; 32]>,
    prev_rx_hp_key: Option<[u8; 32]>,
    prev_rx_iv: Option<[u8; 12]>,
    prev_rx_cipher: Option<ChaCha20Poly1305>,
}

impl CryptoContext {
    pub fn from_shared_secret(
        shared_secret: [u8; 32],
        my_scid: &[u8],
        peer_dcid: &[u8],
        psk: Option<[u8; 32]>,
        is_client: bool,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(shared_secret);
        if my_scid < peer_dcid {
            hasher.update(my_scid);
            hasher.update(peer_dcid);
        } else {
            hasher.update(peer_dcid);
            hasher.update(my_scid);
        }
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
            is_client,
            prev_rx_key: None,
            prev_rx_hp_key: None,
            prev_rx_iv: None,
            prev_rx_cipher: None,
        };
        ctx.derive_keys(0, is_client);
        ctx
    }

    pub fn initial(dcid: &[u8], is_client: bool) -> Self {
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
            is_client,
            prev_rx_key: None,
            prev_rx_hp_key: None,
            prev_rx_iv: None,
            prev_rx_cipher: None,
        };
        ctx.derive_keys(0, is_client);
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

    fn derive_keys(&mut self, epoch: u64, is_client: bool) {
        self.epoch = epoch;
        
        let mut hasher_tx = Sha256::new();
        hasher_tx.update(self.master_secret);
        hasher_tx.update(if is_client { b"client_key" } else { b"server_key" });
        hasher_tx.update(epoch.to_be_bytes());
        self.tx_key.copy_from_slice(&hasher_tx.finalize()[..]);
        self.tx_cipher = ChaCha20Poly1305::new(self.tx_key.as_slice().into());

        let mut hasher_rx = Sha256::new();
        hasher_rx.update(self.master_secret);
        hasher_rx.update(if is_client { b"server_key" } else { b"client_key" });
        hasher_rx.update(epoch.to_be_bytes());
        self.rx_key.copy_from_slice(&hasher_rx.finalize()[..]);
        self.rx_cipher = ChaCha20Poly1305::new(self.rx_key.as_slice().into());

        let mut hasher_tx_hp = Sha256::new();
        hasher_tx_hp.update(self.master_secret);
        hasher_tx_hp.update(if is_client { b"client_hp" } else { b"server_hp" });
        hasher_tx_hp.update(epoch.to_be_bytes());
        self.tx_hp_key.copy_from_slice(&hasher_tx_hp.finalize()[..]);

        let mut hasher_rx_hp = Sha256::new();
        hasher_rx_hp.update(self.master_secret);
        hasher_rx_hp.update(if is_client { b"server_hp" } else { b"client_hp" });
        hasher_rx_hp.update(epoch.to_be_bytes());
        self.rx_hp_key.copy_from_slice(&hasher_rx_hp.finalize()[..]);

        let mut hasher_tx_iv = Sha256::new();
        hasher_tx_iv.update(self.master_secret);
        hasher_tx_iv.update(if is_client { b"client_iv" } else { b"server_iv" });
        hasher_tx_iv.update(epoch.to_be_bytes());
        let tx_iv_hash = hasher_tx_iv.finalize();
        self.tx_iv.copy_from_slice(&tx_iv_hash[..12]);

        let mut hasher_rx_iv = Sha256::new();
        hasher_rx_iv.update(self.master_secret);
        hasher_rx_iv.update(if is_client { b"server_iv" } else { b"client_iv" });
        hasher_rx_iv.update(epoch.to_be_bytes());
        let rx_iv_hash = hasher_rx_iv.finalize();
        self.rx_iv.copy_from_slice(&rx_iv_hash[..12]);
    }

    pub fn rotate_keys(&mut self) {
        self.prev_rx_key = Some(self.rx_key);
        self.prev_rx_hp_key = Some(self.rx_hp_key);
        self.prev_rx_iv = Some(self.rx_iv);
        self.prev_rx_cipher = Some(self.rx_cipher.clone());

        let mut hasher = Sha256::new();
        hasher.update(self.master_secret);
        hasher.update(b"ratchet");
        self.master_secret.copy_from_slice(&hasher.finalize()[..]);
        self.derive_keys(self.epoch + 1, self.is_client);
    }

    pub fn encrypt_in_place(
        &self,
        packet_number: u64,
        aad: &[u8],
        payload: &mut [u8],
    ) -> Result<[u8; 16]> {
        let nonce = self.generate_nonce(packet_number, true, false);
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
        use_prev_key: bool,
    ) -> Result<()> {
        let nonce = self.generate_nonce(packet_number, false, use_prev_key);
        let chacha_tag = chacha20poly1305::Tag::from_slice(tag);
        
        let cipher = if use_prev_key {
            self.prev_rx_cipher.as_ref().ok_or_else(|| ZtError::Crypto("No previous RX cipher available".into()))?
        } else {
            &self.rx_cipher
        };

        cipher.decrypt_in_place_detached(&nonce, aad, payload, chacha_tag)
            .map_err(|e| ZtError::Crypto(format!("Decryption failed: {}", e)))
    }

    fn generate_nonce(&self, packet_number: u64, is_tx: bool, use_prev_key: bool) -> Nonce {
        let iv = if is_tx {
            &self.tx_iv
        } else if use_prev_key {
            self.prev_rx_iv.as_ref().unwrap_or(&self.rx_iv)
        } else {
            &self.rx_iv
        };

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

    pub fn apply_header_protection(&self, header: &mut [u8], payload: &[u8], pn_offset: usize) -> Result<()> {
        if payload.len() < 16 {
            return Ok(());
        }
        
        let mut counter = [0u8; 4];
        counter.copy_from_slice(&payload[0..4]); 
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&payload[4..16]); 

        let mut cipher = ChaCha20::new_from_slices(&self.tx_hp_key, &nonce)
            .map_err(|_| ZtError::Crypto("Invalid HP key or nonce length".into()))?;
        
        let counter_val = u32::from_le_bytes(counter);
        cipher.seek((counter_val as u64) * 64);
        
        let mut mask = [0u8; 5];
        cipher.apply_keystream(&mut mask);
        
        let is_long = (header[0] & 0x80) != 0;
        let first_mask = mask[0] & if is_long { 0x0F } else { 0x1F };
        header[0] ^= first_mask;
        
        // Protocol encodes PN as u64 but only the first 4 bytes are protected.
        let pn_len = 4;
        for i in 0..pn_len { 
            if pn_offset + i < header.len() {
                header[pn_offset + i] ^= mask[i + 1]; 
            }
        }
        
        Ok(())
    }

    pub fn remove_header_protection(&self, packet: &mut [u8], pn_offset: usize, use_prev_key: bool) -> Result<()> {
        let sample_offset = pn_offset + 8;
        if sample_offset + 16 > packet.len() {
            return Err(ZtError::InvalidPacket("Packet too short to resolve header protection".into()));
        }
        
        let mut counter = [0u8; 4];
        counter.copy_from_slice(&packet[sample_offset..sample_offset + 4]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&packet[sample_offset + 4..sample_offset + 16]);

        let hp_key = if use_prev_key {
            self.prev_rx_hp_key.as_ref().ok_or_else(|| ZtError::Crypto("No previous RX HP key available".into()))?
        } else {
            &self.rx_hp_key
        };

        let mut cipher = ChaCha20::new_from_slices(hp_key, &nonce)
            .map_err(|_| ZtError::Crypto("Invalid HP key or nonce length".into()))?;
        
        let counter_val = u32::from_le_bytes(counter);
        cipher.seek((counter_val as u64) * 64);
        
        let mut mask = [0u8; 5];
        cipher.apply_keystream(&mut mask);
        
        let is_long = (packet[0] & 0x80) != 0;
        let first_mask = mask[0] & if is_long { 0x0F } else { 0x1F };
        packet[0] ^= first_mask;
        
        // Must match apply_header_protection().
        let pn_len = 4;
        for i in 0..pn_len { 
            if pn_offset + i < packet.len() {
                packet[pn_offset + i] ^= mask[i + 1]; 
            }
        }
        
        Ok(())
    }
}
