use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};

/// Generates a new X25519 ephemeral keypair for Diffie-Hellman key exchange.
///
/// Uses `EphemeralSecret` instead of `StaticSecret` to guarantee true
/// forward secrecy: the secret is consumed on DH computation and cannot
/// be reused or retained.
pub(crate) fn generate_keypair() -> (EphemeralSecret, PublicKey) {
    let secret = EphemeralSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// Computes a shared secret using our ephemeral private key and the peer's
/// public key, returning the raw bytes.
///
/// The `EphemeralSecret` is consumed (moved) by `diffie_hellman`, so it
/// cannot be accidentally reused — enforced at compile time.
///
/// The intermediate `SharedSecret` bytes are wrapped in `Zeroizing` to
/// guarantee they are wiped from the stack when the guard drops.
pub(crate) fn compute_shared_secret(my_secret: EphemeralSecret, their_public: PublicKey) -> zeroize::Zeroizing<[u8; 32]> {
    let shared: SharedSecret = my_secret.diffie_hellman(&their_public);
    zeroize::Zeroizing::new(shared.to_bytes())
}
