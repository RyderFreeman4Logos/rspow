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
    /// The solver encountered a runtime failure.
    #[error("solver failed: {0}")]
    SolverFailed(String),
    /// The internal channel between solver threads was closed unexpectedly.
    #[error("solver channel closed")]
    ChannelClosed,
}
