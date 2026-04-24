use crate::error::Error;
use crate::error::VerifyError;
use crate::near_stateless::cache::ReplayCache;
use crate::near_stateless::prf::DeterministicNonceProvider;
use crate::near_stateless::time::TimeProvider;
use crate::near_stateless::types::{SolveParams, Submission, VerifierConfig};
use crate::near_stateless::{cache::ReplayCacheError, client::derive_master_challenge};
use left_right::{Absorb, ReadHandle, WriteHandle};
use std::sync::{Arc, Mutex};

/// Errors produced by [`NearStatelessVerifier`] operations.
#[derive(Debug, thiserror::Error)]
pub enum NsError {
    /// The submission timestamp is older than the configured time window.
    #[error("timestamp too old")]
    StaleTimestamp,
    /// The submission timestamp is in the future relative to the server clock.
    #[error("timestamp is in the future")]
    FutureTimestamp,
    /// The client nonce has already been accepted within the time window.
    #[error("replay detected")]
    Replay,
    /// The proof bundle's master challenge does not match the server's derivation.
    #[error("master challenge mismatch")]
    MasterChallengeMismatch,
    /// The proof bundle failed cryptographic verification.
    #[error("verification failed: {0}")]
    Verify(#[from] VerifyError),
    /// The verifier configuration is invalid.
    #[error("invalid config: {0}")]
    InvalidConfig(String),
    /// The replay cache backend returned an error.
    #[error("replay cache error: {0}")]
    Cache(#[from] ReplayCacheError),
    /// The internal left-right config read handle was unexpectedly closed.
    #[error("config read handle closed")]
    ConfigReadHandleClosed,
}

/// Update messages for left-right config.
enum ConfigUpdate {
    Set(VerifierConfig),
}

impl Absorb<ConfigUpdate> for VerifierConfig {
    fn absorb_first(&mut self, update: &mut ConfigUpdate, _first: &Self) {
        match update {
            ConfigUpdate::Set(cfg) => *self = cfg.clone(),
        }
    }

    fn sync_with(&mut self, first: &Self) {
        *self = first.clone();
    }
}

/// Server-side verifier helper for near-stateless PoW submissions.
pub struct NearStatelessVerifier<P: DeterministicNonceProvider, C: ReplayCache, T: TimeProvider> {
    config_r: ReadHandle<VerifierConfig>,
    config_w: Mutex<WriteHandle<VerifierConfig, ConfigUpdate>>,
    nonce_provider: Arc<P>,
    replay_cache: Arc<C>,
    time_provider: Arc<T>,
    server_secret: [u8; 32],
}

impl<P, C, T> NearStatelessVerifier<P, C, T>
where
    P: DeterministicNonceProvider + 'static,
    C: ReplayCache + 'static,
    T: TimeProvider + 'static,
{
    /// Create a new verifier with the given configuration and dependencies.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConfig`] if `config` fails validation.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # #[cfg(feature = "near-stateless")]
    /// # {
    /// use rspow::near_stateless::server::NearStatelessVerifier;
    /// use rspow::near_stateless::prf::Blake3NonceProvider;
    /// use rspow::near_stateless::cache::MokaReplayCache;
    /// use rspow::near_stateless::time::SystemTimeProvider;
    /// use rspow::near_stateless::types::VerifierConfig;
    /// use std::sync::Arc;
    /// use std::time::Duration;
    ///
    /// let config = VerifierConfig {
    ///     time_window: Duration::from_secs(30),
    ///     min_difficulty: 1,
    ///     min_required_proofs: 1,
    /// };
    /// let verifier = NearStatelessVerifier::new(
    ///     config,
    ///     [0xAA; 32],
    ///     Arc::new(Blake3NonceProvider),
    ///     Arc::new(MokaReplayCache::new(10_000)),
    ///     Arc::new(SystemTimeProvider),
    /// )
    /// .expect("valid config");
    /// # }
    /// ```
    pub fn new(
        config: VerifierConfig,
        server_secret: [u8; 32],
        nonce_provider: Arc<P>,
        replay_cache: Arc<C>,
        time_provider: Arc<T>,
    ) -> Result<Self, Error> {
        config.validate()?;
        let (mut config_w, config_r) = left_right::new::<VerifierConfig, ConfigUpdate>();
        config_w.append(ConfigUpdate::Set(config));
        config_w.publish();
        Ok(Self {
            config_r,
            config_w: Mutex::new(config_w),
            nonce_provider,
            replay_cache,
            time_provider,
            server_secret,
        })
    }

    /// Update verifier configuration at runtime.
    ///
    /// The `config_w` mutex is only locked briefly during config publish;
    /// poisoning is recoverable, so we transparently use the inner state
    /// via `unwrap_or_else(|e| e.into_inner())` poison recovery.
    pub fn set_config(&self, new_config: VerifierConfig) -> Result<(), Error> {
        new_config.validate()?;
        let mut wh = self.config_w.lock().unwrap_or_else(|e| e.into_inner());
        wh.append(ConfigUpdate::Set(new_config));
        wh.publish();
        Ok(())
    }

    /// Create parameters to send to a client: timestamp, deterministic nonce, and current config.
    ///
    /// # Errors
    ///
    /// Returns [`NsError::ConfigReadHandleClosed`] if the internal config
    /// read handle has been dropped (should not happen during normal operation).
    pub fn issue_params(&self) -> Result<SolveParams, NsError> {
        let ts = self.time_provider.now_seconds();
        let det = self.nonce_provider.derive(self.server_secret, ts);
        let cfg = self
            .config_r
            .enter()
            .map(|g| g.clone())
            .ok_or(NsError::ConfigReadHandleClosed)?;
        Ok(SolveParams {
            timestamp: ts,
            deterministic_nonce: det,
            config: cfg,
        })
    }

    /// Verify a submission against server policy using the provided secret.
    pub fn verify_submission(&self, submission: &Submission) -> Result<(), NsError> {
        let cfg = self
            .config_r
            .enter()
            .map(|g| g.clone())
            .ok_or(NsError::ConfigReadHandleClosed)?;

        let now = self.time_provider.now_seconds();
        let ts = submission.timestamp;

        if ts > now {
            return Err(NsError::FutureTimestamp);
        }
        let age = std::time::Duration::from_secs(now.saturating_sub(ts));
        if age > cfg.time_window {
            return Err(NsError::StaleTimestamp);
        }

        // Compute expiry for replay cache: ts + window
        let expires_at = ts.saturating_add(cfg.time_window.as_secs());

        // Recompute deterministic nonce and master challenge
        let det_nonce = self.nonce_provider.derive(self.server_secret, ts);
        let master_challenge = derive_master_challenge(det_nonce, submission.client_nonce);

        if submission.proof_bundle.master_challenge != master_challenge {
            return Err(NsError::MasterChallengeMismatch);
        }

        submission
            .proof_bundle
            .verify_strict(cfg.min_difficulty, cfg.min_required_proofs)?;

        let inserted =
            self.replay_cache
                .insert_if_absent(submission.client_nonce, expires_at, now)?;
        if !inserted {
            return Err(NsError::Replay);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::equix::engine::EquixEngineBuilder;
    use crate::near_stateless::client::{
        build_submission, solve_submission, solve_submission_from_params,
    };
    use crate::near_stateless::prf::DeterministicNonceProvider;
    use crate::near_stateless::time::TimeProvider;
    use crate::pow::PowEngine;
    use std::collections::HashMap;
    use std::sync::atomic::AtomicU64;

    #[derive(Default, Clone)]
    struct MapReplayCache {
        map: Arc<Mutex<HashMap<[u8; 32], u64>>>,
    }

    impl ReplayCache for MapReplayCache {
        fn insert_if_absent(
            &self,
            client_nonce: [u8; 32],
            expires_at: u64,
            now: u64,
        ) -> Result<bool, ReplayCacheError> {
            let mut map = self.map.lock().unwrap();
            if let Some(exp) = map.get(&client_nonce) {
                if *exp > now {
                    return Ok(false);
                }
            }
            map.insert(client_nonce, expires_at);
            Ok(true)
        }
    }

    #[derive(Clone, Copy, Default)]
    struct TestNonceProvider;

    impl DeterministicNonceProvider for TestNonceProvider {
        fn derive(&self, secret: [u8; 32], ts: u64) -> [u8; 32] {
            let mut out = secret;
            out[..8].copy_from_slice(&ts.to_le_bytes());
            out
        }
    }

    #[derive(Clone, Copy)]
    struct FixedTimeProvider {
        now: u64,
    }

    impl TimeProvider for FixedTimeProvider {
        fn now_seconds(&self) -> u64 {
            self.now
        }
    }

    fn make_engine(bits: u32, required: usize) -> EquixEngineBuilder {
        EquixEngineBuilder::default()
            .bits(bits)
            .threads(1)
            .required_proofs(required)
            .progress(Arc::new(AtomicU64::new(0)))
    }

    fn solve_one(
        engine: &mut crate::equix::engine::EquixEngine,
        det: [u8; 32],
        client_nonce: [u8; 32],
        ts: u64,
    ) -> Submission {
        solve_submission(engine, ts, det, client_nonce).expect("solve should succeed")
    }

    fn verifier_with(
        cfg: VerifierConfig,
        time: impl TimeProvider + 'static,
        replay: impl ReplayCache + 'static,
    ) -> NearStatelessVerifier<TestNonceProvider, impl ReplayCache, impl TimeProvider> {
        NearStatelessVerifier::new(
            cfg,
            [42u8; 32],
            Arc::new(TestNonceProvider),
            Arc::new(replay),
            Arc::new(time),
        )
        .expect("config should be valid")
    }

    #[test]
    fn config_rejects_subsecond_window() {
        let cfg = VerifierConfig {
            time_window: std::time::Duration::from_millis(900),
            min_difficulty: 1,
            min_required_proofs: 1,
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn config_rejects_non_integer_seconds() {
        let cfg = VerifierConfig {
            time_window: std::time::Duration::from_millis(1_500),
            ..Default::default()
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn verify_submission_happy_path() {
        let mut engine = make_engine(1, 1).build_validated().unwrap();
        let cfg = VerifierConfig {
            time_window: std::time::Duration::from_secs(10),
            ..Default::default()
        };
        let ts = 1_000;
        let now = 1_004;
        let det = TestNonceProvider.derive([42u8; 32], ts);
        let client_nonce = [7u8; 32];
        let submission = solve_one(&mut engine, det, client_nonce, ts);

        let verifier = verifier_with(cfg, FixedTimeProvider { now }, MapReplayCache::default());

        assert!(verifier.verify_submission(&submission).is_ok());
    }

    #[test]
    fn rejects_future_timestamp() {
        let mut engine = make_engine(1, 1).build_validated().unwrap();
        let ts = 10;
        let det = TestNonceProvider.derive([1u8; 32], ts);
        let submission = solve_one(&mut engine, det, [2u8; 32], ts);
        let verifier = verifier_with(
            VerifierConfig::default(),
            FixedTimeProvider { now: 5 },
            MapReplayCache::default(),
        );

        match verifier.verify_submission(&submission) {
            Err(NsError::FutureTimestamp) => {}
            other => panic!("expected future timestamp, got {:?}", other),
        }
    }

    #[test]
    fn rejects_stale_timestamp() {
        let mut engine = make_engine(1, 1).build_validated().unwrap();
        let cfg = VerifierConfig {
            time_window: std::time::Duration::from_secs(5),
            ..Default::default()
        };
        let ts = 10;
        let det = TestNonceProvider.derive([3u8; 32], ts);
        let submission = solve_one(&mut engine, det, [4u8; 32], ts);
        let verifier = verifier_with(
            cfg,
            FixedTimeProvider { now: 16 },
            MapReplayCache::default(),
        );

        match verifier.verify_submission(&submission) {
            Err(NsError::StaleTimestamp) => {}
            other => panic!("expected stale, got {:?}", other),
        }
    }

    #[test]
    fn accepts_window_lower_bound_inclusively() {
        let mut engine = make_engine(1, 1).build_validated().unwrap();
        let cfg = VerifierConfig {
            time_window: std::time::Duration::from_secs(5),
            ..Default::default()
        };
        // ts exactly at now - window
        let ts = 10;
        let det = TestNonceProvider.derive([42u8; 32], ts);
        let submission = solve_one(&mut engine, det, [41u8; 32], ts);
        let verifier = verifier_with(
            cfg,
            FixedTimeProvider { now: 15 },
            MapReplayCache::default(),
        );

        assert!(verifier.verify_submission(&submission).is_ok());
    }

    #[test]
    fn detects_replay() {
        let mut engine = make_engine(1, 1).build_validated().unwrap();
        let cfg = VerifierConfig {
            time_window: std::time::Duration::from_secs(10),
            ..Default::default()
        };
        let ts = 100;
        let det = TestNonceProvider.derive([42u8; 32], ts);
        let submission = solve_one(&mut engine, det, [6u8; 32], ts);
        let verifier = verifier_with(
            cfg,
            FixedTimeProvider { now: 103 },
            MapReplayCache::default(),
        );

        verifier
            .verify_submission(&submission)
            .expect("first verify should succeed");

        match verifier.verify_submission(&submission) {
            Err(NsError::Replay) => {}
            other => panic!("expected replay, got {:?}", other),
        }
    }

    #[test]
    fn config_update_applies_to_verification() {
        let mut engine = make_engine(1, 1).build_validated().unwrap();
        let ts = 200;
        let det = TestNonceProvider.derive([42u8; 32], ts);
        let submission = solve_one(&mut engine, det, [9u8; 32], ts);
        let verifier = verifier_with(
            VerifierConfig {
                time_window: std::time::Duration::from_secs(10),
                ..Default::default()
            },
            FixedTimeProvider { now: 205 },
            MapReplayCache::default(),
        );

        let new_cfg = VerifierConfig {
            time_window: std::time::Duration::from_secs(10),
            min_required_proofs: 2,
            ..Default::default()
        };
        verifier.set_config(new_cfg).unwrap();

        match verifier.verify_submission(&submission) {
            Err(NsError::Verify(VerifyError::InvalidDifficulty)) => {}
            other => panic!("expected difficulty error, got {:?}", other),
        }
    }

    #[test]
    fn master_challenge_mismatch_is_rejected() {
        let mut engine = make_engine(1, 1).build_validated().unwrap();
        let ts = 50;
        let det = TestNonceProvider.derive([11u8; 32], ts);
        let submission = solve_one(&mut engine, det, [12u8; 32], ts);
        let verifier = verifier_with(
            VerifierConfig {
                time_window: std::time::Duration::from_secs(10),
                ..Default::default()
            },
            FixedTimeProvider { now: 55 },
            MapReplayCache::default(),
        );

        match verifier.verify_submission(&submission) {
            Err(NsError::MasterChallengeMismatch) => {}
            other => panic!("expected mismatch, got {:?}", other),
        }
    }

    #[test]
    fn build_submission_is_equivalent_to_struct_literal() {
        let mut engine = make_engine(1, 1).build_validated().unwrap();
        let ts = 70;
        let det = TestNonceProvider.derive([13u8; 32], ts);
        let client_nonce = [14u8; 32];
        let master = derive_master_challenge(det, client_nonce);
        let bundle = engine.solve_bundle(master).expect("solve should succeed");

        let via_helper = build_submission(ts, client_nonce, bundle.clone());
        let direct = Submission {
            timestamp: ts,
            client_nonce,
            proof_bundle: bundle,
        };

        assert_eq!(via_helper.timestamp, direct.timestamp);
        assert_eq!(via_helper.client_nonce, direct.client_nonce);
        assert_eq!(
            via_helper.proof_bundle.proofs.len(),
            direct.proof_bundle.proofs.len()
        );
    }

    #[test]
    fn issue_params_and_solve_round_trip() {
        let cfg = VerifierConfig {
            time_window: std::time::Duration::from_secs(10),
            min_difficulty: 1,
            min_required_proofs: 1,
        };
        let mut engine = make_engine(1, 1).build_validated().unwrap();
        let verifier = verifier_with(
            cfg.clone(),
            FixedTimeProvider { now: 1_000 },
            MapReplayCache::default(),
        );

        let params = verifier
            .issue_params()
            .expect("issue_params should succeed");
        assert_eq!(params.config, cfg);
        assert_eq!(params.timestamp, 1_000);

        let client_nonce = [77u8; 32];
        let submission = solve_submission_from_params(&mut engine, &params, client_nonce)
            .expect("solve from params");

        assert_eq!(submission.timestamp, params.timestamp);
        assert_eq!(submission.client_nonce, client_nonce);

        verifier
            .verify_submission(&submission)
            .expect("round-trip verify");
    }

    #[test]
    fn ns_error_config_read_handle_closed_display() {
        let e = NsError::ConfigReadHandleClosed;
        assert_eq!(e.to_string(), "config read handle closed");
    }

    #[test]
    fn set_config_rejects_time_window_too_small() {
        let verifier = verifier_with(
            VerifierConfig::default(),
            FixedTimeProvider { now: 100 },
            MapReplayCache::default(),
        );
        let bad_cfg = VerifierConfig {
            time_window: std::time::Duration::from_millis(500),
            ..Default::default()
        };
        assert_eq!(
            verifier.set_config(bad_cfg).unwrap_err(),
            Error::TimeWindowTooSmall
        );
    }

    #[test]
    fn set_config_rejects_non_integral_seconds() {
        let verifier = verifier_with(
            VerifierConfig::default(),
            FixedTimeProvider { now: 100 },
            MapReplayCache::default(),
        );
        let bad_cfg = VerifierConfig {
            time_window: std::time::Duration::from_millis(2_500),
            ..Default::default()
        };
        assert_eq!(
            verifier.set_config(bad_cfg).unwrap_err(),
            Error::TimeWindowMustBeIntegralSeconds
        );
    }

    #[test]
    fn set_config_rejects_min_difficulty_zero() {
        let verifier = verifier_with(
            VerifierConfig::default(),
            FixedTimeProvider { now: 100 },
            MapReplayCache::default(),
        );
        let bad_cfg = VerifierConfig {
            min_difficulty: 0,
            ..Default::default()
        };
        assert_eq!(
            verifier.set_config(bad_cfg).unwrap_err(),
            Error::MinDifficultyMustBeNonZero
        );
    }

    #[test]
    fn set_config_rejects_min_required_proofs_zero() {
        let verifier = verifier_with(
            VerifierConfig::default(),
            FixedTimeProvider { now: 100 },
            MapReplayCache::default(),
        );
        let bad_cfg = VerifierConfig {
            min_required_proofs: 0,
            ..Default::default()
        };
        assert_eq!(
            verifier.set_config(bad_cfg).unwrap_err(),
            Error::MinRequiredProofsMustBeNonZero
        );
    }
}
