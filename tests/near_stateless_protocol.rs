#![cfg(all(feature = "equix", feature = "near-stateless"))]

use rspow::near_stateless::cache::{ReplayCache, ReplayCacheError};
use rspow::near_stateless::client::{derive_master_challenge, solve_submission};
use rspow::near_stateless::prf::DeterministicNonceProvider;
use rspow::near_stateless::server::{NearStatelessVerifier, NsError};
use rspow::near_stateless::time::TimeProvider;
use rspow::near_stateless::types::VerifierConfig;
use rspow::EquixEngineBuilder;
use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Duration;

// --- inline test doubles (no shared state between files) ---

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

fn make_verifier(
    cfg: VerifierConfig,
    now: u64,
) -> NearStatelessVerifier<TestNonceProvider, MapReplayCache, FixedTimeProvider> {
    NearStatelessVerifier::new(
        cfg,
        [42u8; 32],
        Arc::new(TestNonceProvider),
        Arc::new(MapReplayCache::default()),
        Arc::new(FixedTimeProvider { now }),
    )
    .expect("verifier config should be valid")
}

#[test]
fn full_protocol_accepts_valid_submission() {
    let cfg = VerifierConfig {
        time_window: Duration::from_secs(60),
        min_difficulty: 1,
        min_required_proofs: 1,
    };
    let now = 1_005_u64;
    let verifier = make_verifier(cfg, now);

    let params = verifier
        .issue_params()
        .expect("issue_params should succeed");
    assert_eq!(params.timestamp, now);

    let client_nonce = [42u8; 32];
    let progress = Arc::new(AtomicU64::new(0));
    let mut engine = EquixEngineBuilder::default()
        .bits(1_u32)
        .threads(1_usize)
        .required_proofs(1_usize)
        .progress(progress)
        .build_validated()
        .expect("engine build");

    // Derive master challenge and solve.
    let det_nonce = params.deterministic_nonce;
    let submission = solve_submission(&mut engine, params.timestamp, det_nonce, client_nonce)
        .expect("solve should succeed");

    // Verify the master challenge was correctly derived.
    let expected_master = derive_master_challenge(det_nonce, client_nonce);
    assert_eq!(submission.proof_bundle.master_challenge, expected_master);

    verifier
        .verify_submission(&submission)
        .expect("valid submission should pass verification");
}

#[test]
fn full_protocol_rejects_replay() {
    let cfg = VerifierConfig {
        time_window: Duration::from_secs(60),
        min_difficulty: 1,
        min_required_proofs: 1,
    };
    let now = 2_000_u64;
    let verifier = make_verifier(cfg, now);

    let params = verifier.issue_params().expect("issue_params");
    let client_nonce = [42u8; 32];

    let progress = Arc::new(AtomicU64::new(0));
    let mut engine = EquixEngineBuilder::default()
        .bits(1_u32)
        .threads(1_usize)
        .required_proofs(1_usize)
        .progress(progress)
        .build_validated()
        .expect("engine build");

    let submission = solve_submission(
        &mut engine,
        params.timestamp,
        params.deterministic_nonce,
        client_nonce,
    )
    .expect("solve");

    // First submission succeeds.
    verifier
        .verify_submission(&submission)
        .expect("first verify should succeed");

    // Second submission with identical nonce is rejected as replay.
    match verifier.verify_submission(&submission) {
        Err(NsError::Replay) => {} // expected
        other => panic!("expected NsError::Replay, got {:?}", other),
    }
}
