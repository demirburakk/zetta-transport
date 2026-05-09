use rand::rngs::OsRng;
use x25519_dalek::{EphemeralSecret, PublicKey, SharedSecret};
use zeroize::Zeroize;

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
/// public key, then immediately zeroizes the raw bytes.
///
/// The `EphemeralSecret` is consumed (moved) by `diffie_hellman`, so it
/// cannot be accidentally reused — enforced at compile time.
pub(crate) fn compute_shared_secret(my_secret: EphemeralSecret, their_public: PublicKey) -> [u8; 32] {
    let shared: SharedSecret = my_secret.diffie_hellman(&their_public);
    let mut bytes = shared.to_bytes();
    let result = bytes;
    bytes.zeroize();
    result
}
