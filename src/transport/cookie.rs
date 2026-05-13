use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use std::net::SocketAddr;
use std::time::Instant;
use std::sync::OnceLock;

/// Returns a monotonic time in milliseconds since the process started.
pub(crate) fn current_time_millis() -> u64 {
    static BASE: OnceLock<Instant> = OnceLock::new();
    BASE.get_or_init(Instant::now).elapsed().as_millis() as u64
}

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

/// Maximum age in milliseconds for a retry cookie to remain valid.
///
/// A tight window (5000ms) limits replay attack surface while comfortably
/// covering even high-latency network round-trips.
const COOKIE_MAX_AGE_MS: u64 = 5000;

/// Verifies a retry cookie against the client's address and SCID.
///
/// Returns false if the cookie is expired (>5000ms) or the HMAC doesn't match.
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

    if now < cookie_time || now - cookie_time > COOKIE_MAX_AGE_MS {
        return false;
    }

    let expected = make_retry_cookie(cookie_key, addr, client_scid, cookie_time);
    subtle::ConstantTimeEq::ct_eq(&expected[8..40], &cookie[8..40]).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn make_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080)
    }

    #[test]
    fn cookie_verify_valid() {
        let key = [1u8; 32];
        let addr = make_addr();
        let scid = b"client_scid";
        let now = 1000u64;

        let cookie = make_retry_cookie(&key, &addr, scid, now);
        assert!(verify_retry_cookie(&key, &addr, scid, &cookie, now));
    }

    #[test]
    fn cookie_verify_expired() {
        let key = [1u8; 32];
        let addr = make_addr();
        let scid = b"client_scid";
        let cookie = make_retry_cookie(&key, &addr, scid, 1000);
        assert!(!verify_retry_cookie(&key, &addr, scid, &cookie, 6001));
    }

    #[test]
    fn cookie_verify_wrong_ip() {
        let key = [1u8; 32];
        let addr1 = make_addr();
        let addr2 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)), 8080);
        let scid = b"client_scid";
        let cookie = make_retry_cookie(&key, &addr1, scid, 1000);
        assert!(!verify_retry_cookie(&key, &addr2, scid, &cookie, 1000));
    }

    #[test]
    fn cookie_verify_wrong_scid() {
        let key = [1u8; 32];
        let addr = make_addr();
        let cookie = make_retry_cookie(&key, &addr, b"scid_A", 1000);
        assert!(!verify_retry_cookie(&key, &addr, b"scid_B", &cookie, 1000));
    }

    #[test]
    fn cookie_wrong_length_rejected() {
        let key = [1u8; 32];
        let addr = make_addr();
        assert!(!verify_retry_cookie(&key, &addr, b"scid", b"too_short", 1000));
        assert!(!verify_retry_cookie(&key, &addr, b"scid", &[0u8; 50], 1000));
    }

    #[test]
    fn cookie_timing_boundary() {
        let key = [1u8; 32];
        let addr = make_addr();
        let scid = b"s";
        let cookie = make_retry_cookie(&key, &addr, scid, 1000);
        assert!(verify_retry_cookie(&key, &addr, scid, &cookie, 6000));
        assert!(!verify_retry_cookie(&key, &addr, scid, &cookie, 6001));
    }
}
