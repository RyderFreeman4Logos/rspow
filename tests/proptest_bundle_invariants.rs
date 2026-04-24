#![cfg(feature = "equix")]

use proptest::prelude::*;
use rspow::equix::{Proof, ProofBundle, ProofConfig};

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn bundle_proofs_are_sorted_by_id(seeds in proptest::collection::vec(any::<u64>(), 1..=16)) {
        // insert_proof maintains sorted order, so the result must be sorted.
        // Uses dummy challenge/solution — insert_proof only checks duplicate ids
        // and maintains sort order without verifying the PoW.
        let master = [0xAAu8; 32];

        let mut bundle = ProofBundle {
            proofs: Vec::new(),
            config: ProofConfig { bits: 1 },
            master_challenge: master,
        };

        let mut seen = std::collections::HashSet::new();
        for &seed in &seeds {
            if !seen.insert(seed) {
                continue;
            }
            let proof = Proof {
                id: seed,
                challenge: [0u8; 32],
                solution: [0u8; 16],
            };
            bundle.insert_proof(proof).expect("insert should succeed for unique id");
        }

        prop_assert_eq!(bundle.proofs.len(), seen.len(), "bundle should contain all unique seeds");
        for window in bundle.proofs.windows(2) {
            prop_assert!(
                window[0].id < window[1].id,
                "proofs must be strictly sorted by id"
            );
        }
    }

    #[test]
    fn bundle_rejects_duplicate_ids(id in any::<u64>()) {
        let master = [0xBBu8; 32];

        let mut bundle = ProofBundle {
            proofs: Vec::new(),
            config: ProofConfig { bits: 1 },
            master_challenge: master,
        };

        let proof = Proof {
            id,
            challenge: [0u8; 32],
            solution: [0u8; 16],
        };

        bundle.insert_proof(proof).expect("first insert should succeed");

        let duplicate = Proof {
            id,
            challenge: [0u8; 32],
            solution: [0u8; 16],
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

// Test core::derive_challenge determinism.
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
