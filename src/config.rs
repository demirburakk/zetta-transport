//! Validated endpoint configuration.
//!
//! Construct [`ZtConfig`](crate::config::ZtConfig) with struct update syntax, then pass it to
//! [`crate::transport::endpoint::ZtEndpoint::bind_with_zt_config`]. Both peers advertise and
//! authenticate their receive limits during the handshake.

use crate::transport::CongestionControlAlgorithm;
use std::time::Duration;

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
    pub initial_max_data: u64,
    /// Maximum total stream buffer memory per connection. Default: 64 MB.
    pub max_connection_buffer: usize,

    // -- Network --
    /// Minimum MTU used as the initial value and PMTUD lower bound. Default: 1200.
    pub mtu_min: usize,
    /// Maximum MTU that PMTUD will probe up to. Default: 9000.
    pub mtu_max: usize,
    /// Interval between path-MTU probes. Default: 15 seconds.
    pub mtu_probe_interval: Duration,

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

    /// Endpoint-scoped packet loss/reordering injection used by tests.
    #[cfg(any(test, feature = "testing"))]
    pub simulation: crate::simulation::SimulationConfig,
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
            mtu_probe_interval: Duration::from_secs(15),

            cookie_max_age_ms: 5000,
            key_update_packet_interval: 1 << 20,
            psk: None,
            max_path_validation_retries: 3,

            cc_algorithm: CongestionControlAlgorithm::Cubic,

            #[cfg(any(test, feature = "testing"))]
            simulation: crate::simulation::SimulationConfig::default(),
        }
    }
}

impl ZtConfig {
    /// Validates values that affect wire-format bounds, resource limits, and
    /// timer progress. Endpoint construction calls this automatically.
    pub fn validate(&self) -> crate::error::Result<()> {
        use crate::error::ZtError;

        if self.connect_timeout.is_zero() {
            return Err(ZtError::InvalidConfiguration(
                "connect_timeout must be greater than zero".into(),
            ));
        }
        if self.idle_timeout.as_millis() == 0 || self.idle_timeout.as_millis() > u64::MAX as u128 {
            return Err(ZtError::InvalidConfiguration(
                "idle_timeout must fit in a non-zero millisecond wire value".into(),
            ));
        }
        if self.max_concurrent_streams == 0 || self.max_concurrent_streams > (u32::MAX / 2) as u64 {
            return Err(ZtError::InvalidConfiguration(
                "max_concurrent_streams must be in 1..=u32::MAX/2".into(),
            ));
        }
        if self.alpn.is_empty() || self.alpn.len() > u8::MAX as usize {
            return Err(ZtError::InvalidConfiguration(
                "alpn length must be in 1..=255 bytes".into(),
            ));
        }
        if self.initial_stream_window == 0 || self.initial_stream_window > self.max_stream_window {
            return Err(ZtError::InvalidConfiguration(
                "initial_stream_window must be non-zero and no larger than max_stream_window"
                    .into(),
            ));
        }
        if self.max_stream_window > self.max_connection_buffer as u64
            || usize::try_from(self.max_stream_window).is_err()
        {
            return Err(ZtError::InvalidConfiguration(
                "max_stream_window must fit in usize and max_connection_buffer".into(),
            ));
        }
        if self.initial_max_data == 0 || self.initial_max_data > u32::MAX as u64 {
            return Err(ZtError::InvalidConfiguration(
                "initial_max_data must be in 1..=u32::MAX (ACK wire limit)".into(),
            ));
        }
        if self.max_connection_buffer == 0 {
            return Err(ZtError::InvalidConfiguration(
                "max_connection_buffer must be greater than zero".into(),
            ));
        }
        if self.initial_max_data > self.max_connection_buffer as u64 {
            return Err(ZtError::InvalidConfiguration(
                "initial_max_data must not exceed max_connection_buffer".into(),
            ));
        }
        if self.mtu_min < 1200 || self.mtu_min > self.mtu_max {
            return Err(ZtError::InvalidConfiguration(
                "mtu_min must be at least 1200 and no larger than mtu_max".into(),
            ));
        }
        if self.mtu_probe_interval.is_zero() {
            return Err(ZtError::InvalidConfiguration(
                "mtu_probe_interval must be greater than zero".into(),
            ));
        }
        // 65,507 is the maximum IPv4 UDP payload. Reserve protocol overhead
        // so a configured path MTU can always be emitted as one datagram.
        if self.mtu_max > 65_507 {
            return Err(ZtError::InvalidConfiguration(
                "mtu_max must not exceed the UDP payload limit (65507)".into(),
            ));
        }
        if self.cookie_max_age_ms == 0 {
            return Err(ZtError::InvalidConfiguration(
                "cookie_max_age_ms must be greater than zero".into(),
            ));
        }
        if self.key_update_packet_interval == 0 {
            return Err(ZtError::InvalidConfiguration(
                "key_update_packet_interval must be greater than zero".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::ZtConfig;

    #[test]
    fn default_configuration_is_valid() {
        ZtConfig::default().validate().unwrap();
    }

    #[test]
    fn rejects_wire_incompatible_limits() {
        let config = ZtConfig {
            initial_max_data: u32::MAX as u64 + 1,
            ..ZtConfig::default()
        };
        assert!(config.validate().is_err());
    }
}
