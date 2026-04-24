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
    fn now_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}
