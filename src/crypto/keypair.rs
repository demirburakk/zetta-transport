use rand::rngs::OsRng;
use x25519_dalek::{PublicKey, StaticSecret};

/// Generates a new X25519 keypair for Diffie-Hellman key exchange.
pub(crate) fn generate_keypair() -> (StaticSecret, PublicKey) {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);
    (secret, public)
}

/// Computes a shared secret using our private key and the peer's public key.
pub(crate) fn compute_shared_secret(my_secret: &StaticSecret, their_public: PublicKey) -> [u8; 32] {
    my_secret.diffie_hellman(&their_public).to_bytes()
}
