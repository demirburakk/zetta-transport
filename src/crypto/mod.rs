use crate::error::{Result, ZtError};
use chacha20::ChaCha20;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{AeadInPlace, KeyInit},
};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

/// Version-specific fixed salt for the Initial packet crypto context.
/// This is public knowledge (version-pinned), which is correct: Initial
/// packets provide only anti-spoofing, not secrecy. Both sides derive the
/// same Initial keys deterministically so they can decode each other's
/// un-established handshake packets.
const INITIAL_SALT: &[u8] = b"ZettaTransport v1 InitialSalt\x00\x00\x00";

pub struct CryptoContext {
    secret: [u8; 32],
    // Keys are internal; access via encrypt/decrypt APIs only.
    tx_key: [u8; 32],
    rx_key: [u8; 32],
    tx_hp_key: [u8; 32],
    rx_hp_key: [u8; 32],
    tx_iv: [u8; 12],
    rx_iv: [u8; 12],
    tx_cipher: ChaCha20Poly1305,
    rx_cipher: ChaCha20Poly1305,
    pub epoch: u64,
    is_client: bool,

    // Fallback keys for out-of-order packets during key phase rotations.
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
        let mut ikm = Vec::with_capacity(32 + 16 + 32);
        ikm.extend_from_slice(&shared_secret);
        // Canonicalize CID order so both sides produce the same IKM regardless
        // of which side is "us".
        if my_scid < peer_dcid {
            ikm.extend_from_slice(my_scid);
            ikm.extend_from_slice(peer_dcid);
        } else {
            ikm.extend_from_slice(peer_dcid);
            ikm.extend_from_slice(my_scid);
        }
        if let Some(key) = psk {
            ikm.extend_from_slice(&key);
        }

        let salt = b"ZettaTransport v1";
        let (_, hk) = Hkdf::<Sha256>::extract(Some(salt), &ikm);
        let mut secret = [0u8; 32];
        hk.expand(b"master_secret", &mut secret)
            .expect("HKDF expand failed");

        let mut ctx = Self {
            secret,
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

    /// Creates an Initial-packet crypto context.
    ///
    /// Initial packets use a *version-specific static salt* (not the DCID) as
    /// the HKDF salt, mirroring the QUIC approach (RFC 9001 §5.2).  The DCID
    /// is included as the IKM so both endpoints arrive at the same keys while
    /// still binding the context to this specific connection attempt.
    ///
    /// This means Initial keys are deterministic and **not secret** — they
    /// provide only packet authentication (anti-spoofing), not confidentiality.
    /// Actual confidentiality begins after the Handshake phase.
    pub fn initial(dcid: &[u8], is_client: bool) -> Self {
        // Extract: PRK = HKDF-Extract(salt=INITIAL_SALT, IKM=dcid)
        let (_, hk) = Hkdf::<Sha256>::extract(Some(INITIAL_SALT), dcid);
        let mut secret = [0u8; 32];
        // Expand a distinct "initial_secret" label so this PRK slot is unique.
        hk.expand(b"initial_secret", &mut secret)
            .expect("HKDF expand failed");

        let mut ctx = Self {
            secret,
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

    pub fn compute_shared_secret(my_secret: &StaticSecret, their_public: PublicKey) -> [u8; 32] {
        my_secret.diffie_hellman(&their_public).to_bytes()
    }

    /// Derives all per-direction keys from `self.secret` for the given epoch.
    ///
    /// The epoch number is encoded into every HKDF label so that rotating the
    /// secret (ratchet) but keeping the same PRK by accident still produces
    /// distinct key material across epochs.
    fn derive_keys(&mut self, epoch: u64, is_client: bool) {
        self.epoch = epoch;
        let hk = Hkdf::<Sha256>::from_prk(&self.secret).expect("Invalid PRK");

        // Encode epoch into labels to prevent label collision across epochs.
        let epoch_suffix = format!(":{epoch}");

        let mk_label = |base: &str| -> Vec<u8> {
            let mut l = base.as_bytes().to_vec();
            l.extend_from_slice(epoch_suffix.as_bytes());
            l
        };

        let (tx_label, rx_label) = if is_client {
            (mk_label("client_key"), mk_label("server_key"))
        } else {
            (mk_label("server_key"), mk_label("client_key"))
        };

        let (tx_hp_label, rx_hp_label) = if is_client {
            (mk_label("client_hp"), mk_label("server_hp"))
        } else {
            (mk_label("server_hp"), mk_label("client_hp"))
        };

        let (tx_iv_label, rx_iv_label) = if is_client {
            (mk_label("client_iv"), mk_label("server_iv"))
        } else {
            (mk_label("server_iv"), mk_label("client_iv"))
        };

        hk.expand(&tx_label, &mut self.tx_key)
            .expect("HKDF expand tx_key failed");
        self.tx_cipher = ChaCha20Poly1305::new(self.tx_key.as_slice().into());

        hk.expand(&rx_label, &mut self.rx_key)
            .expect("HKDF expand rx_key failed");
        self.rx_cipher = ChaCha20Poly1305::new(self.rx_key.as_slice().into());

        hk.expand(&tx_hp_label, &mut self.tx_hp_key)
            .expect("HKDF expand tx_hp failed");
        hk.expand(&rx_hp_label, &mut self.rx_hp_key)
            .expect("HKDF expand rx_hp failed");

        hk.expand(&tx_iv_label, &mut self.tx_iv)
            .expect("HKDF expand tx_iv failed");
        hk.expand(&rx_iv_label, &mut self.rx_iv)
            .expect("HKDF expand rx_iv failed");
    }

    pub fn rotate_keys(&mut self) {
        self.prev_rx_key = Some(self.rx_key);
        self.prev_rx_hp_key = Some(self.rx_hp_key);
        self.prev_rx_iv = Some(self.rx_iv);
        self.prev_rx_cipher = Some(self.rx_cipher.clone());

        let mut next_secret = [0u8; 32];
        Hkdf::<Sha256>::new(None, &self.secret)
            .expand(b"ratchet", &mut next_secret)
            .expect("HKDF ratchet failed");
        self.secret.zeroize();
        self.secret = next_secret;

        self.derive_keys(self.epoch + 1, self.is_client);
    }

    pub fn encrypt_in_place(
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
            self.prev_rx_cipher
                .as_ref()
                .ok_or_else(|| ZtError::Crypto("No previous RX cipher available".into()))?
        } else {
            &self.rx_cipher
        };

        cipher
            .decrypt_in_place_detached(&nonce, aad, payload, chacha_tag)
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

        // QUIC-style nonce: IV XOR PacketNumber (right-aligned, big-endian)
        nonce_bytes.copy_from_slice(iv);
        for i in 0..8 {
            nonce_bytes[12 - 8 + i] ^= pn_bytes[i];
        }

        *Nonce::from_slice(&nonce_bytes)
    }

    /// Applies header protection to a packet in-place.
    ///
    /// The mask is generated by running ChaCha20 with:
    ///   - key  = hp_key
    ///   - counter = 0  (fixed, per the spec intent)
    ///   - nonce = sample[0..12]  (first 12 bytes of the 16-byte sample)
    ///
    /// Only the first 5 bytes of the keystream block are used as the mask,
    /// which is the amount needed to cover the first header byte and up to
    /// 4 packet-number bytes.
    pub fn apply_header_protection(&self, packet: &mut [u8], pn_offset: usize) -> Result<()> {
        let sample_offset = pn_offset + 4; // Sample starts 4 bytes after PN field
        if packet.len() < sample_offset + 16 {
            return Ok(());
        }

        let sample = &packet[sample_offset..sample_offset + 16];

        // Use sample[0..12] as the nonce (counter is implicitly 0 in the first
        // block that ChaCha20 produces after initialization).
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&sample[0..12]);

        let mut cipher = ChaCha20::new_from_slices(&self.tx_hp_key, &nonce)
            .map_err(|_| ZtError::Crypto("Invalid HP key or nonce length".into()))?;

        // Generate exactly 5 bytes of keystream from the first ChaCha20 block
        // (counter=0). ChaCha20::new_from_slices starts at counter=0.
        let mut mask = [0u8; 5];
        cipher.apply_keystream(&mut mask);

        let is_long = (packet[0] & 0x80) != 0;
        let first_mask = mask[0] & if is_long { 0x0F } else { 0x1F };
        packet[0] ^= first_mask;

        for i in 0..4 {
            if pn_offset + i < packet.len() {
                packet[pn_offset + i] ^= mask[i + 1];
            }
        }

        Ok(())
    }

    /// Removes header protection from a received packet in-place.
    ///
    /// Must use the same sample/nonce derivation as `apply_header_protection`.
    pub fn remove_header_protection(
        &self,
        packet: &mut [u8],
        pn_offset: usize,
        use_prev_key: bool,
    ) -> Result<()> {
        let sample_offset = pn_offset + 4;
        if sample_offset + 16 > packet.len() {
            return Err(ZtError::InvalidPacket(
                "Packet too short to remove header protection".into(),
            ));
        }

        let mut sample = [0u8; 16];
        sample.copy_from_slice(&packet[sample_offset..sample_offset + 16]);

        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&sample[0..12]);

        let hp_key = if use_prev_key {
            self.prev_rx_hp_key
                .as_ref()
                .ok_or_else(|| ZtError::Crypto("No previous RX HP key available".into()))?
        } else {
            &self.rx_hp_key
        };

        let mut cipher = ChaCha20::new_from_slices(hp_key, &nonce)
            .map_err(|_| ZtError::Crypto("Invalid HP key or nonce length".into()))?;

        let mut mask = [0u8; 5];
        cipher.apply_keystream(&mut mask);

        let is_long = (packet[0] & 0x80) != 0;
        let first_mask = mask[0] & if is_long { 0x0F } else { 0x1F };
        packet[0] ^= first_mask;

        for i in 0..4 {
            if pn_offset + i < packet.len() {
                packet[pn_offset + i] ^= mask[i + 1];
            }
        }

        Ok(())
    }
}
