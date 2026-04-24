#![cfg(feature = "equix")]

use proptest::prelude::*;
use rspow::equix::{EquixEngineBuilder, Proof, ProofBundle, ProofConfig};
use rspow::pow::PowEngine;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

proptest! {
    // Fewer cases: each invocation solves an EquiX puzzle (~100ms).
    #![proptest_config(ProptestConfig::with_cases(32))]

    #[test]
    fn bundle_proofs_are_sorted_by_id(seeds in proptest::collection::vec(any::<u64>(), 1..=16)) {
        // Build a ProofBundle by inserting proofs with random ids.
        // insert_proof maintains sorted order, so the result must be sorted.
        let master = [0xAAu8; 32];

        // Solve a small bundle to get a valid proof template (correct challenge + solution).
        let progress = Arc::new(AtomicU64::new(0));
        let mut engine = EquixEngineBuilder::default()
            .bits(1_u32)
            .threads(1_usize)
            .required_proofs(1_usize)
            .progress(progress)
            .build_validated()
            .expect("engine build");
        let template_bundle = engine.solve_bundle(master).expect("solve");
        let template_proof = template_bundle.proofs[0];

        // Create an empty bundle and insert proofs with unique ids from seeds.
        let mut bundle = ProofBundle {
            proofs: Vec::new(),
            config: ProofConfig { bits: 1 },
            master_challenge: master,
        };

        // Deduplicate seeds to avoid DuplicateProof errors.
        let mut seen = std::collections::HashSet::new();
        for &seed in &seeds {
            if !seen.insert(seed) {
                continue;
            }
            // Use the template proof's solution/challenge (won't pass verify_strict
            // but insert_proof only checks duplicate ids and maintains sort order).
            let proof = Proof {
                id: seed,
                challenge: template_proof.challenge,
                solution: template_proof.solution,
            };
            bundle.insert_proof(proof).expect("insert should succeed for unique id");
        }

        // Assert sorted order.
        let ids: Vec<u64> = bundle.proofs.iter().map(|p| p.id).collect();
        for window in ids.windows(2) {
            prop_assert!(
                window[0] < window[1],
                "proofs must be strictly sorted by id, got {:?}",
                ids
            );
        }
    }

    #[test]
    fn bundle_rejects_duplicate_ids(id in any::<u64>()) {
        let master = [0xBBu8; 32];

        let progress = Arc::new(AtomicU64::new(0));
        let mut engine = EquixEngineBuilder::default()
            .bits(1_u32)
            .threads(1_usize)
            .required_proofs(1_usize)
            .progress(progress)
            .build_validated()
            .expect("engine build");
        let template_bundle = engine.solve_bundle(master).expect("solve");
        let template_proof = template_bundle.proofs[0];

        let proof = Proof {
            id,
            challenge: template_proof.challenge,
            solution: template_proof.solution,
        };

        let mut bundle = ProofBundle {
            proofs: Vec::new(),
            config: ProofConfig { bits: 1 },
            master_challenge: master,
        };

        bundle.insert_proof(proof).expect("first insert should succeed");

        // Second insert with same id must fail.
        let duplicate = Proof {
            id,
            challenge: template_proof.challenge,
            solution: template_proof.solution,
        };
        let err = bundle
            .insert_proof(duplicate)
            .expect_err("duplicate id should be rejected");
        prop_assert!(
            matches!(err, rspow::VerifyError::DuplicateProof),
            "expected DuplicateProof, got {:?}",
            err
        );
    }
}

// Test derive_master_challenge determinism via the near_stateless client module.
// Feature-gated on equix only (derive_master_challenge is in near_stateless,
// but we can test the lower-level core::derive_challenge which is always available
// and has the same determinism property).

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn derive_challenge_determinism(
        master in any::<[u8; 32]>(),
        proof_id in any::<u64>()
    ) {
        let c1 = rspow::core::derive_challenge(master, proof_id);
        let c2 = rspow::core::derive_challenge(master, proof_id);
        prop_assert_eq!(c1, c2, "same inputs must produce same challenge");
    }

    #[test]
    fn derive_challenge_sensitivity(
        a in any::<[u8; 32]>(),
        b in any::<[u8; 32]>(),
        proof_id in any::<u64>()
    ) {
        prop_assume!(a != b);
        let c_a = rspow::core::derive_challenge(a, proof_id);
        let c_b = rspow::core::derive_challenge(b, proof_id);
        prop_assert_ne!(
            c_a, c_b,
            "different master challenges must produce different per-proof challenges"
        );
    }
}
