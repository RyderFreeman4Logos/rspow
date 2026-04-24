use thiserror::Error;

/// Errors produced when verifying a proof or proof bundle.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum VerifyError {
    /// A proof with the same id appears more than once in a bundle.
    #[error("duplicate proof")]
    DuplicateProof,
    /// The proof or bundle does not meet the required difficulty threshold.
    #[error("proof does not meet difficulty")]
    InvalidDifficulty,
    /// The proof data is structurally invalid (bad challenge, unsorted ids, etc.).
    #[error("malformed proof or bundle")]
    Malformed,
}

/// Errors produced by engine configuration, solving, or internal channels.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Error {
    /// A configuration parameter is out of range or inconsistent.
    #[error("invalid config: {0}")]
    InvalidConfig(String),

    /// The `bits` (difficulty) parameter must be at least 1.
    #[error("invalid config: bits must be > 0")]
    BitsMustBeNonZero,

    /// The `threads` parameter must be at least 1.
    #[error("invalid config: threads must be >= 1")]
    ThreadsMustBeNonZero,

    /// The `required_proofs` parameter must be at least 1.
    #[error("invalid config: required_proofs must be >= 1")]
    RequiredProofsMustBeNonZero,

    /// The `progress` handle is required but was not provided.
    #[error("invalid config: progress must be provided")]
    ProgressMissing,

    /// The `min_difficulty` parameter must be at least 1.
    #[error("invalid config: min_difficulty must be >= 1")]
    MinDifficultyMustBeNonZero,

    /// The `time_window` must be at least one full second.
    #[error("invalid config: time_window must be at least 1 second")]
    TimeWindowTooSmall,

    /// The `time_window` must be a whole number of seconds (no sub-second component).
    #[error("invalid config: time_window must be a whole number of seconds")]
    TimeWindowMustBeIntegralSeconds,

    /// The `min_required_proofs` parameter must be at least 1.
    #[error("invalid config: min_required_proofs must be >= 1")]
    MinRequiredProofsMustBeNonZero,

    /// The solver encountered a runtime failure.
    #[error("solver failed: {0}")]
    SolverFailed(String),
    /// The internal channel between solver threads was closed unexpectedly.
    #[error("solver channel closed")]
    ChannelClosed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bits_must_be_non_zero_display() {
        let e = Error::BitsMustBeNonZero;
        assert_eq!(e.to_string(), "invalid config: bits must be > 0");
    }

    #[test]
    fn threads_must_be_non_zero_display() {
        let e = Error::ThreadsMustBeNonZero;
        assert_eq!(e.to_string(), "invalid config: threads must be >= 1");
    }

    #[test]
    fn required_proofs_must_be_non_zero_display() {
        let e = Error::RequiredProofsMustBeNonZero;
        assert_eq!(
            e.to_string(),
            "invalid config: required_proofs must be >= 1"
        );
    }

    #[test]
    fn progress_missing_display() {
        let e = Error::ProgressMissing;
        assert_eq!(e.to_string(), "invalid config: progress must be provided");
    }

    #[test]
    fn min_difficulty_must_be_non_zero_display() {
        let e = Error::MinDifficultyMustBeNonZero;
        assert_eq!(e.to_string(), "invalid config: min_difficulty must be >= 1");
    }

    #[test]
    fn time_window_too_small_display() {
        let e = Error::TimeWindowTooSmall;
        assert_eq!(
            e.to_string(),
            "invalid config: time_window must be at least 1 second"
        );
    }

    #[test]
    fn time_window_must_be_integral_seconds_display() {
        let e = Error::TimeWindowMustBeIntegralSeconds;
        assert_eq!(
            e.to_string(),
            "invalid config: time_window must be a whole number of seconds"
        );
    }

    #[test]
    fn min_required_proofs_must_be_non_zero_display() {
        let e = Error::MinRequiredProofsMustBeNonZero;
        assert_eq!(
            e.to_string(),
            "invalid config: min_required_proofs must be >= 1"
        );
    }

    #[test]
    fn invalid_config_catch_all_still_works() {
        let e = Error::InvalidConfig("custom message".into());
        assert_eq!(e.to_string(), "invalid config: custom message");
    }

    #[test]
    fn structured_variants_are_eq() {
        assert_eq!(Error::BitsMustBeNonZero, Error::BitsMustBeNonZero);
        assert_ne!(Error::BitsMustBeNonZero, Error::ThreadsMustBeNonZero);
    }
}
