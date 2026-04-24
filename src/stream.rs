use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Atomic counter that hands out sequential nonce values to solver threads.
#[derive(Debug)]
pub struct NonceSource {
    next: AtomicU64,
}

impl NonceSource {
    /// Create a new source starting at `start`.
    pub const fn new(start: u64) -> Self {
        Self {
            next: AtomicU64::new(start),
        }
    }

    /// Atomically fetch the current nonce and advance the counter.
    #[inline]
    pub fn fetch(&self) -> u64 {
        self.next.fetch_add(1, Ordering::Relaxed)
    }
}

/// Shared flag that solver threads poll to know when to stop.
#[derive(Debug)]
pub struct StopFlag {
    stop: AtomicBool,
}

impl StopFlag {
    /// Create a new flag in the *not stopped* state.
    pub const fn new() -> Self {
        Self {
            stop: AtomicBool::new(false),
        }
    }

    /// Return `true` if the flag has been raised.
    #[inline]
    pub fn should_stop(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    /// Raise the stop flag so all polling threads will exit.
    pub fn force_stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }
}

impl Default for StopFlag {
    fn default() -> Self {
        Self::new()
    }
}
