use moka::sync::Cache;

/// Error type for replay cache operations.
#[derive(Debug, thiserror::Error)]
pub enum ReplayCacheError {
    #[error("replay cache operation failed: {0}")]
    Other(String),
}

/// Replay cache abstraction for preventing duplicate client_nonce submissions.
pub trait ReplayCache: Send + Sync {
    /// Insert the nonce with the given expiry (unix seconds) if absent or expired.
    /// Returns `Ok(true)` if inserted, `Ok(false)` if it already existed and is still valid.
    fn insert_if_absent(
        &self,
        client_nonce: [u8; 32],
        expires_at: u64,
        now: u64,
    ) -> Result<bool, ReplayCacheError>;
}

/// In-memory replay cache backed by `moka::sync::Cache` storing expiry timestamps.
#[derive(Debug, Clone)]
pub struct MokaReplayCache {
    inner: Cache<[u8; 32], u64>,
}

impl MokaReplayCache {
    pub fn new(max_capacity: u64) -> Self {
        Self {
            inner: Cache::builder().max_capacity(max_capacity).build(),
        }
    }
}

impl ReplayCache for MokaReplayCache {
    fn insert_if_absent(
        &self,
        client_nonce: [u8; 32],
        expires_at: u64,
        now: u64,
    ) -> Result<bool, ReplayCacheError> {
        let entry = self
            .inner
            .entry(client_nonce)
            .or_insert_with_if(|| expires_at, |current_exp| *current_exp <= now);

        Ok(entry.is_fresh() || entry.is_old_value_replaced())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::Arc, thread};

    #[test]
    fn allows_only_single_acceptance_under_concurrency() {
        let cache = Arc::new(MokaReplayCache::new(1_000));
        let nonce = [7u8; 32];
        let accepts = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        thread::scope(|s| {
            for _ in 0..16 {
                let cache = Arc::clone(&cache);
                let accepts = Arc::clone(&accepts);
                s.spawn(move || {
                    let inserted = cache
                        .insert_if_absent(nonce, 10, 0)
                        .expect("insert should succeed");
                    if inserted {
                        accepts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    }
                });
            }
        });

        assert_eq!(accepts.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn reinserts_when_expired() {
        let cache = MokaReplayCache::new(100);
        let nonce = [1u8; 32];

        assert!(cache
            .insert_if_absent(nonce, 5, 0)
            .expect("first insert succeeds"));

        // Still valid at now=4 -> should reject as duplicate.
        assert!(!cache
            .insert_if_absent(nonce, 10, 4)
            .expect("duplicate rejected"));

        // Expired at now=6 -> should allow reinsertion.
        assert!(cache
            .insert_if_absent(nonce, 12, 6)
            .expect("expired entry should be replaced"));
    }
}
