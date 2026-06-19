use std::sync::atomic::{AtomicU32, Ordering};

static LOSS_RATE_PCT: AtomicU32 = AtomicU32::new(0);
static REORDER_RATE_PCT: AtomicU32 = AtomicU32::new(0);
static REORDER_DELAY_MS: AtomicU32 = AtomicU32::new(0);

/// Sets the packet loss rate as a percentage (0 to 100).
pub fn set_loss_rate(pct: u32) {
    LOSS_RATE_PCT.store(pct.min(100), Ordering::Relaxed);
}

/// Sets the packet reordering rate as a percentage (0 to 100).
pub fn set_reorder_rate(pct: u32) {
    REORDER_RATE_PCT.store(pct.min(100), Ordering::Relaxed);
}

/// Sets the delay in milliseconds for reordered packets.
pub fn set_reorder_delay(delay_ms: u32) {
    REORDER_DELAY_MS.store(delay_ms, Ordering::Relaxed);
}

/// Returns the current packet loss rate percentage.
pub fn get_loss_rate() -> u32 {
    LOSS_RATE_PCT.load(Ordering::Relaxed)
}

/// Returns the current packet reordering rate percentage.
pub fn get_reorder_rate() -> u32 {
    REORDER_RATE_PCT.load(Ordering::Relaxed)
}

/// Returns the current packet reordering delay in milliseconds.
pub fn get_reorder_delay() -> u32 {
    REORDER_DELAY_MS.load(Ordering::Relaxed)
}
