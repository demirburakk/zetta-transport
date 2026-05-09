use chacha20poly1305::{ChaCha20Poly1305, aead::KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

/// Version-specific fixed salt for the Initial packet crypto context.
/// This is public knowledge (version-pinned), which is correct: Initial
/// packets provide only anti-spoofing, not secrecy. Both sides derive the
/// same Initial keys deterministically so they can decode each other's
/// un-established handshake packets.
pub(super) const INITIAL_SALT: &[u8] = b"ZettaTransport v1 InitialSalt\x00\x00\x00";

/// Derives a master secret from a shared secret, connection IDs, and optional PSK.
///
/// CID order is canonicalized so both sides produce the same IKM regardless
/// of which side is "us".
pub(super) fn derive_master_secret(
    shared_secret: &[u8; 32],
    my_scid: &[u8],
    peer_dcid: &[u8],
    psk: Option<[u8; 32]>,
    is_client: bool,
) -> [u8; 32] {
    let mut ikm = Vec::with_capacity(32 + 16 + 32);
    ikm.extend_from_slice(shared_secret);
    // Explicitly separate roles instead of lexicographical sorting.
    // Client and Server must append in the same order (Client SCID, then Server SCID).
    // If we are the client, my_scid is Client SCID. If server, peer_dcid is Client SCID.
    if is_client {
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
    secret
}

/// Derives an initial secret from the DCID using the version-specific salt.
///
/// Initial packets use a *version-specific static salt* (not the DCID) as
/// the HKDF salt, mirroring the QUIC approach (RFC 9001 §5.2). The DCID
/// is included as the IKM so both endpoints arrive at the same keys while
/// still binding the context to this specific connection attempt.
pub(super) fn derive_initial_secret(dcid: &[u8]) -> [u8; 32] {
    let (_, hk) = Hkdf::<Sha256>::extract(Some(INITIAL_SALT), dcid);
    let mut secret = [0u8; 32];
    hk.expand(b"initial_secret", &mut secret)
        .expect("HKDF expand failed");
    secret
}

/// Output container for all per-direction keys derived from a single epoch.
pub(super) struct EpochKeys {
    pub tx_key: [u8; 32],
    pub rx_key: [u8; 32],
    pub tx_hp_key: [u8; 16],
    pub rx_hp_key: [u8; 16],
    pub tx_iv: [u8; 12],
    pub rx_iv: [u8; 12],
    pub tx_cipher: ChaCha20Poly1305,
    pub rx_cipher: ChaCha20Poly1305,
}

/// Derives all per-direction keys from `secret` for the given epoch.
///
/// The epoch number is encoded into every HKDF label so that rotating the
/// secret (ratchet) but keeping the same PRK by accident still produces
/// distinct key material across epochs.
pub(super) fn derive_epoch_keys(secret: &[u8; 32], epoch: u64, is_client: bool) -> EpochKeys {
    let hk = Hkdf::<Sha256>::from_prk(secret).expect("Invalid PRK");

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

    let mut keys = EpochKeys {
        tx_key: [0u8; 32],
        rx_key: [0u8; 32],
        tx_hp_key: [0u8; 16],
        rx_hp_key: [0u8; 16],
        tx_iv: [0u8; 12],
        rx_iv: [0u8; 12],
        tx_cipher: ChaCha20Poly1305::new([0u8; 32].as_slice().into()),
        rx_cipher: ChaCha20Poly1305::new([0u8; 32].as_slice().into()),
    };

    hk.expand(&tx_label, &mut keys.tx_key)
        .expect("HKDF expand tx_key failed");
    keys.tx_cipher = ChaCha20Poly1305::new(keys.tx_key.as_slice().into());

    hk.expand(&rx_label, &mut keys.rx_key)
        .expect("HKDF expand rx_key failed");
    keys.rx_cipher = ChaCha20Poly1305::new(keys.rx_key.as_slice().into());

    hk.expand(&tx_hp_label, &mut keys.tx_hp_key)
        .expect("HKDF expand tx_hp failed");
    hk.expand(&rx_hp_label, &mut keys.rx_hp_key)
        .expect("HKDF expand rx_hp failed");

    hk.expand(&tx_iv_label, &mut keys.tx_iv)
        .expect("HKDF expand tx_iv failed");
    hk.expand(&rx_iv_label, &mut keys.rx_iv)
        .expect("HKDF expand rx_iv failed");

    keys
}

/// Ratchets the secret forward, zeroizing the old secret.
///
/// Returns the new secret to use for subsequent epochs.
///
/// Uses a domain-separated, version-specific label to avoid accidental
/// collisions with other HKDF-Expand calls in the protocol.
pub(super) fn ratchet_secret(current_secret: &mut [u8; 32]) -> [u8; 32] {
    let mut next_secret = [0u8; 32];
    Hkdf::<Sha256>::new(None, current_secret)
        .expand(b"ZettaTransport v1 ratchet secret", &mut next_secret)
        .expect("HKDF ratchet failed");
    current_secret.zeroize();
    next_secret
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_master_secret_symmetric() {
        let shared = [42u8; 32];
        let client_scid = b"client01";
        let server_scid = b"server01";

        let client_secret = derive_master_secret(&shared, client_scid, server_scid, None, true);
        let server_secret = derive_master_secret(&shared, server_scid, client_scid, None, false);
        assert_eq!(client_secret, server_secret);
    }

    #[test]
    fn derive_master_secret_psk_changes_result() {
        let shared = [1u8; 32];
        let scid = b"abc";
        let dcid = b"xyz";
        let no_psk = derive_master_secret(&shared, scid, dcid, None, true);
        let with_psk = derive_master_secret(&shared, scid, dcid, Some([99u8; 32]), true);
        assert_ne!(no_psk, with_psk);
    }

    #[test]
    fn epoch_keys_client_server_differ() {
        let secret = [7u8; 32];
        let client_keys = derive_epoch_keys(&secret, 0, true);
        let server_keys = derive_epoch_keys(&secret, 0, false);
        assert_eq!(client_keys.tx_key, server_keys.rx_key);
        assert_eq!(client_keys.rx_key, server_keys.tx_key);
        assert_eq!(client_keys.tx_hp_key, server_keys.rx_hp_key);
    }

    #[test]
    fn epoch_suffix_produces_different_keys() {
        let secret = [3u8; 32];
        let epoch0 = derive_epoch_keys(&secret, 0, true);
        let epoch1 = derive_epoch_keys(&secret, 1, true);
        assert_ne!(epoch0.tx_key, epoch1.tx_key);
    }

    #[test]
    fn ratchet_produces_different_secret() {
        let mut secret = [5u8; 32];
        let original = secret;
        let next = ratchet_secret(&mut secret);
        assert_ne!(original, next);
        assert_eq!(secret, [0u8; 32]);
    }

    #[test]
    fn ratchet_is_deterministic() {
        let mut s1 = [9u8; 32];
        let mut s2 = [9u8; 32];
        let r1 = ratchet_secret(&mut s1);
        let r2 = ratchet_secret(&mut s2);
        assert_eq!(r1, r2);
    }
}
