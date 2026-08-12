//! Read-only connection telemetry.
//!
//! Obtain a snapshot with [`crate::stream::ZtConnectionHandle::stats`]. Counters are cumulative
//! for the connection; gauges such as congestion window and bytes in flight reflect the instant
//! at which the snapshot was requested.

use crate::transport::congestion::CongestionControlAlgorithm;
use std::time::Duration;

/// Connection-level statistics and telemetry.
///
/// Provides a snapshot of the current connection state including RTT estimates,
/// congestion window, bytes in flight, and other transport-level metrics.
/// Obtain via [`crate::stream::ZtConnectionHandle::stats()`].
#[derive(Debug, Clone)]
pub struct ConnectionStats {
    /// Smoothed Round-Trip Time estimate.
    pub rtt: Duration,
    /// RTT variance (jitter).
    pub rttvar: Duration,
    /// Current congestion window in bytes.
    pub cwnd: usize,
    /// Bytes currently in flight (sent but not yet acknowledged).
    pub bytes_in_flight: usize,
    /// Total bytes sent over this connection.
    pub bytes_sent: usize,
    /// Total bytes received over this connection.
    pub bytes_received: usize,
    /// Number of active streams.
    pub active_streams: usize,
    /// Current key epoch (increments on key rotation).
    pub key_epoch: u64,
    /// Current path MTU in bytes.
    pub mtu: usize,
    /// Current congestion control algorithm.
    pub cc_algorithm: CongestionControlAlgorithm,
    /// Packets declared lost by packet/time thresholds or retransmission timeout.
    pub packets_lost: u64,
    /// Reliable packets transmitted again after loss.
    pub packets_retransmitted: u64,
    /// Successful path-MTU probes.
    pub mtu_probe_successes: u64,
    /// Failed path-MTU probes.
    pub mtu_probe_failures: u64,
    /// Times an established larger MTU was rolled back after black-hole detection.
    pub mtu_blackhole_recoveries: u64,
}
