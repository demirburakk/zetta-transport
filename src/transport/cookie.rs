use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::net::SocketAddr;

type HmacSha256 = Hmac<Sha256>;

/// Creates an HMAC-based retry cookie binding the client's address and SCID.
///
/// The cookie is 40 bytes: 8-byte timestamp + 32-byte HMAC.
pub(crate) fn make_retry_cookie(
    cookie_key: &[u8; 32],
    addr: &SocketAddr,
    client_scid: &[u8],
    now: u64,
) -> [u8; 40] {
    let mut hmac = HmacSha256::new_from_slice(cookie_key).expect("HMAC can take any key size");
    match addr.ip() {
        std::net::IpAddr::V4(v4) => hmac.update(&v4.octets()),
        std::net::IpAddr::V6(v6) => hmac.update(&v6.octets()),
    }
    hmac.update(&addr.port().to_be_bytes());
    hmac.update(client_scid);
    let time_bytes = now.to_be_bytes();
    hmac.update(&time_bytes);
    let cookie_hash = hmac.finalize().into_bytes();

    let mut cookie = [0u8; 40];
    cookie[0..8].copy_from_slice(&time_bytes);
    cookie[8..40].copy_from_slice(&cookie_hash);
    cookie
}

/// Verifies a retry cookie against the client's address and SCID.
///
/// Returns false if the cookie is expired (>30s) or the HMAC doesn't match.
pub(crate) fn verify_retry_cookie(
    cookie_key: &[u8; 32],
    addr: &SocketAddr,
    client_scid: &[u8],
    cookie: &[u8],
    now: u64,
) -> bool {
    if cookie.len() != 40 {
        return false;
    }
    let mut time_bytes = [0u8; 8];
    time_bytes.copy_from_slice(&cookie[0..8]);
    let cookie_time = u64::from_be_bytes(time_bytes);

    if now < cookie_time || now - cookie_time > 30 {
        return false;
    }

    let expected = make_retry_cookie(cookie_key, addr, client_scid, cookie_time);
    subtle::ConstantTimeEq::ct_eq(&expected[8..40], &cookie[8..40]).into()
}
