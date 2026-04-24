#![cfg(all(feature = "equix", feature = "near-stateless"))]

use proptest::prelude::*;
use rspow::near_stateless::types::VerifierConfig;
use std::time::Duration;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn validate_accepts_valid_configs(
        secs in 1_u64..=3600,
        difficulty in 1_u32..=8,
        required in 1_usize..=4,
    ) {
        let cfg = VerifierConfig {
            time_window: Duration::from_secs(secs),
            min_difficulty: difficulty,
            min_required_proofs: required,
        };
        prop_assert!(
            cfg.validate().is_ok(),
            "valid config should pass: secs={secs}, difficulty={difficulty}, required={required}"
        );
    }

    #[test]
    fn validate_rejects_zero_bits(
        secs in 1_u64..=3600,
        required in 1_usize..=4,
    ) {
        let cfg = VerifierConfig {
            time_window: Duration::from_secs(secs),
            min_difficulty: 0,
            min_required_proofs: required,
        };
        prop_assert!(
            cfg.validate().is_err(),
            "bits=0 must be rejected"
        );
    }

    #[test]
    fn validate_rejects_zero_required_proofs(
        secs in 1_u64..=3600,
        difficulty in 1_u32..=8,
    ) {
        let cfg = VerifierConfig {
            time_window: Duration::from_secs(secs),
            min_difficulty: difficulty,
            min_required_proofs: 0,
        };
        prop_assert!(
            cfg.validate().is_err(),
            "required_proofs=0 must be rejected"
        );
    }

    #[test]
    fn validate_rejects_subsecond_window(
        millis in 1_u64..=999,
        difficulty in 1_u32..=8,
        required in 1_usize..=4,
    ) {
        let cfg = VerifierConfig {
            time_window: Duration::from_millis(millis),
            min_difficulty: difficulty,
            min_required_proofs: required,
        };
        prop_assert!(
            cfg.validate().is_err(),
            "time_window < 1s must be rejected: millis={millis}"
        );
    }

    #[test]
    fn validate_rejects_fractional_seconds(
        secs in 1_u64..=3600,
        extra_millis in 1_u32..=999,
        difficulty in 1_u32..=8,
        required in 1_usize..=4,
    ) {
        let cfg = VerifierConfig {
            time_window: Duration::from_secs(secs) + Duration::from_millis(extra_millis as u64),
            min_difficulty: difficulty,
            min_required_proofs: required,
        };
        prop_assert!(
            cfg.validate().is_err(),
            "fractional-second window must be rejected: secs={secs}, extra_ms={extra_millis}"
        );
    }
}
