#![cfg(feature = "equix")]

use rspow::equix::{EquixEngineBuilder, ProofBundle, ProofBundleLimits};
use rspow::pow::{PowBundle, PowEngine};
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

#[test]
fn engine_solve_serialize_deserialize_verify_roundtrip() {
    let progress = Arc::new(AtomicU64::new(0));
    let mut engine = EquixEngineBuilder::default()
        .bits(1_u32)
        .threads(1_usize)
        .required_proofs(2_usize)
        .progress(progress)
        .build_validated()
        .expect("valid config");

    let master_challenge = [0xABu8; 32];
    let bundle = engine
        .solve_bundle(master_challenge)
        .expect("solve should succeed");

    assert_eq!(bundle.proofs().len(), 2, "should have exactly 2 proofs");

    // Serialize with postcard.
    let bytes = postcard::to_allocvec(&bundle).expect("postcard serialize");
    assert!(!bytes.is_empty(), "serialized bytes should not be empty");

    // Deserialize with bounded limits.
    let limits = ProofBundleLimits::default();
    let recovered = ProofBundle::deserialize_bounded(&bytes[..], &limits).expect("bounded deser");

    assert_eq!(
        bundle, recovered,
        "round-tripped bundle must equal original"
    );

    // Verify the recovered bundle passes strict verification.
    recovered
        .verify_strict(1, 2)
        .expect("recovered bundle should verify");
}
