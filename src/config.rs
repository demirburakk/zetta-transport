use std::time::Duration;
use crate::transport::CongestionControlAlgorithm;

/// Configuration parameters for a ZettaTransport endpoint.
///
/// All fields have sensible defaults matching the original hardcoded values.
/// Use `ZtConfig::default()` and then override specific fields as needed.
///
/// # Example
/// ```
/// use zetta_transport::config::ZtConfig;
/// use zetta_transport::transport::CongestionControlAlgorithm;
///
/// let config = ZtConfig {
///     cc_algorithm: CongestionControlAlgorithm::Reno,
///     max_concurrent_streams: 200,
///     ..ZtConfig::default()
/// };
/// ```
#[derive(Debug, Clone)]
pub struct ZtConfig {
    // -- Connection --
    /// Timeout for the initial handshake during `connect()`. Default: 5 seconds.
    pub connect_timeout: Duration,
    /// Duration of inactivity before the connection is closed. Default: 60 seconds.
    pub idle_timeout: Duration,
    /// Maximum number of concurrent streams per connection. Default: 100.
    pub max_concurrent_streams: u64,
    /// ALPN protocol identifier exchanged during handshake. Default: b"zetta".
    pub alpn: Vec<u8>,

    // -- Flow Control --
    /// Initial receive window size per stream in bytes. Default: 1 MB (1,048,576).
    pub initial_stream_window: u64,
    /// Maximum stream receive window after auto-tuning in bytes. Default: 16 MB.
    pub max_stream_window: u64,
    /// Initial connection-level flow control window in bytes. Default: 1 MB.
    pub initial_max_data: u32,
    /// Maximum total stream buffer memory per connection. Default: 64 MB.
    pub max_connection_buffer: usize,

    // -- Network --
    /// Minimum MTU used as the initial value and PMTUD lower bound. Default: 1200.
    pub mtu_min: usize,
    /// Maximum MTU that PMTUD will probe up to. Default: 9000.
    pub mtu_max: usize,

    // -- Security --
    /// Maximum age of a retry cookie before it is rejected. Default: 5000ms.
    pub cookie_max_age_ms: u64,
    /// Number of packets sent before triggering automatic key rotation. Default: 1,048,576.
    pub key_update_packet_interval: u64,
    /// Optional Pre-Shared Key for additional authentication.
    pub psk: Option<[u8; 32]>,
    /// Maximum number of PathChallenge retransmissions before abandoning a new path. Default: 3.
    pub max_path_validation_retries: u32,

    // -- Congestion Control --
    /// Congestion control algorithm used for all connections. Default: Cubic.
    pub cc_algorithm: CongestionControlAlgorithm,
}

impl Default for ZtConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(60),
            max_concurrent_streams: 100,
            alpn: b"zetta".to_vec(),

            initial_stream_window: 1_048_576,
            max_stream_window: 16 * 1024 * 1024,
            initial_max_data: 1_048_576,
            max_connection_buffer: 64 * 1024 * 1024,

            mtu_min: 1200,
            mtu_max: 9000,

            cookie_max_age_ms: 5000,
            key_update_packet_interval: 1 << 20,
            psk: None,
            max_path_validation_retries: 3,

            cc_algorithm: CongestionControlAlgorithm::Cubic,
        }
    }
}
