use std::time::{SystemTime, UNIX_EPOCH};

/// Abstraction to allow testing/time injection.
pub trait TimeProvider: Send + Sync {
    /// Return the current time as seconds since the UNIX epoch.
    fn now_seconds(&self) -> u64;
}

/// [`TimeProvider`] backed by [`SystemTime::now`].
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemTimeProvider;

impl TimeProvider for SystemTimeProvider {
    /// Returns the current wall-clock time as seconds since the UNIX epoch.
    ///
    /// Returns `0` if the system clock is set before `UNIX_EPOCH` (clock
    /// misconfiguration).  Downstream code should treat `0` as a fatal
    /// sentinel — a timestamp of zero will be rejected as stale by any
    /// verifier with a non-degenerate time window.
    fn now_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            // Returns Duration::ZERO when the clock is before UNIX_EPOCH.
            // Changing the trait signature to return Result would be breaking,
            // so we preserve the sentinel-value approach.
            .unwrap_or_default()
            .as_secs()
    }
}
