use std::time::Duration;

use crate::equix::types::ProofBundle;
use crate::error::Error;

/// Configuration used by the near-stateless verifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierConfig {
    /// Maximum age of a submission timestamp before it is considered stale.
    pub time_window: Duration,
    /// Minimum number of leading zero bits required per proof.
    pub min_difficulty: u32,
    /// Minimum number of proofs required per bundle.
    pub min_required_proofs: usize,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            time_window: Duration::from_secs(1),
            min_difficulty: 1,
            min_required_proofs: 1,
        }
    }
}

impl VerifierConfig {
    /// Validate that all fields are within acceptable ranges.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidConfig`] if any field is out of range.
    pub fn validate(&self) -> Result<(), Error> {
        // Require integral seconds to avoid silent truncation.
        if self.time_window < Duration::from_secs(1) {
            return Err(Error::InvalidConfig(
                "time_window must be at least 1 second".into(),
            ));
        }
        if self.time_window.subsec_nanos() != 0 {
            return Err(Error::InvalidConfig(
                "time_window must be a whole number of seconds".into(),
            ));
        }
        if self.min_difficulty == 0 {
            return Err(Error::InvalidConfig("min_difficulty must be >= 1".into()));
        }
        if self.min_required_proofs == 0 {
            return Err(Error::InvalidConfig(
                "min_required_proofs must be >= 1".into(),
            ));
        }
        Ok(())
    }
}

/// Payload submitted by clients for verification.
#[derive(Debug, Clone)]
pub struct Submission {
    /// UNIX timestamp (seconds) at which the client received the challenge.
    pub timestamp: u64,
    /// Random nonce chosen by the client.
    pub client_nonce: [u8; 32],
    /// The solved proof bundle.
    pub proof_bundle: ProofBundle,
}

/// Parameters a server sends to clients for solving.
#[derive(Debug, Clone)]
pub struct SolveParams {
    /// Server-side UNIX timestamp (seconds) embedded in the challenge.
    pub timestamp: u64,
    /// Deterministic nonce derived by the server from its secret and timestamp.
    pub deterministic_nonce: [u8; 32],
    /// Current verifier configuration the client must satisfy.
    pub config: VerifierConfig,
}

/// Errors that can occur while building a [`Submission`].
#[derive(Debug, thiserror::Error)]
pub enum SubmissionBuilderError {
    /// The engine configuration was invalid.
    #[error("invalid config: {0}")]
    InvalidConfig(String),
}
