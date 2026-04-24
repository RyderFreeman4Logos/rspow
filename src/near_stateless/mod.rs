//! Near-stateless PoW helpers (feature-gated).
//!
//! Provides building blocks for the near-stateless protocol described in
//! `docs/near_stateless_pow.md`:
//! - Deterministic nonce derivation (keyed BLAKE3) via a pluggable provider.
//! - Replay cache abstraction with a default in-memory (moka) implementation.
//! - Server-side verifier helper that validates the full submission flow.
//! - Client-side helpers to build master challenges and package submissions.

/// Replay cache abstraction and default in-memory implementation.
pub mod cache;
/// Client-side helpers for challenge derivation and submission building.
pub mod client;
/// Deterministic nonce provider trait and BLAKE3 implementation.
pub mod prf;
/// Server-side verifier for near-stateless submissions.
pub mod server;
/// Time provider abstraction for testability.
pub mod time;
/// Shared data types ([`VerifierConfig`], [`Submission`], [`SolveParams`]).
pub mod types;

pub use crate::near_stateless::client::solve_submission_from_params;
pub use cache::{MokaReplayCache, ReplayCache, ReplayCacheError};
pub use client::build_engine_from_params;
pub use client::{build_submission, derive_master_challenge};
pub use prf::{Blake3NonceProvider, DeterministicNonceProvider};
pub use server::{NearStatelessVerifier, NsError};
pub use time::{SystemTimeProvider, TimeProvider};
pub use types::{SolveParams, Submission, SubmissionBuilderError, VerifierConfig};
