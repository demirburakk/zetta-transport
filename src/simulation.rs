//! Deterministic network fault injection for integration tests.
//!
//! This module is available only with the `testing` feature. Faults are applied to active
//! connection packets sent by the configured endpoint; configure both endpoints to affect both
//! directions. It is intended for tests, never for production traffic shaping.

/// Endpoint-scoped network fault injection settings.
///
/// Keeping these values on each endpoint prevents one parallel test from
/// silently injecting loss into unrelated connections in the same process.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SimulationConfig {
    /// Reproducible seed used independently by every connection actor.
    pub seed: u64,
    /// Percentage of active-connection packets dropped pseudo-randomly, clamped to 0–100.
    pub loss_rate_pct: u32,
    /// Percentage of active-connection packets delayed pseudo-randomly, clamped to 0–100.
    pub reorder_rate_pct: u32,
    /// Delay applied to packets selected for reordering.
    pub reorder_delay_ms: u32,
    /// Deterministically drop every Nth active-connection packet (zero disables it).
    pub drop_every_n: u32,
    /// Drop packets larger than this many bytes to emulate an MTU black hole (zero disables it).
    pub blackhole_mtu: usize,
    /// Period for a deterministic burst-loss window (zero disables it).
    pub burst_period: u32,
    /// Number of packets dropped at the beginning of each burst period.
    pub burst_length: u32,
}

impl SimulationConfig {
    /// Creates a pseudo-random loss and reorder profile.
    ///
    /// Percentages above 100 are clamped. A zero reorder delay disables delayed delivery even
    /// when `reorder_rate_pct` is non-zero.
    pub fn new(loss_rate_pct: u32, reorder_rate_pct: u32, reorder_delay_ms: u32) -> Self {
        Self {
            seed: 0x0005_eed7_e77a,
            loss_rate_pct: loss_rate_pct.min(100),
            reorder_rate_pct: reorder_rate_pct.min(100),
            reorder_delay_ms,
            drop_every_n: 0,
            blackhole_mtu: 0,
            burst_period: 0,
            burst_length: 0,
        }
    }

    /// Overrides the deterministic pseudo-random seed.
    pub fn with_seed(mut self, seed: u64) -> Self {
        self.seed = seed;
        self
    }

    /// Drops every `every_n`th active-connection packet; zero disables periodic loss.
    pub fn with_periodic_drop(mut self, every_n: u32) -> Self {
        self.drop_every_n = every_n;
        self
    }

    /// Drops packets larger than `mtu` bytes; zero disables MTU black-hole simulation.
    pub fn with_blackhole_mtu(mut self, mtu: usize) -> Self {
        self.blackhole_mtu = mtu;
        self
    }

    /// Drops the first `length` packets in each `period`; zero period disables burst loss.
    pub fn with_burst_loss(mut self, period: u32, length: u32) -> Self {
        self.burst_period = period;
        self.burst_length = length.min(period);
        self
    }
}
