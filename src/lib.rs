//! Proof-of-work library built on the [EquiX](https://crates.io/crates/equix) memory-hard puzzle.
//!
//! `rspow` provides a generic [`PowEngine`] trait together with a concrete
//! [EquiX](https://crates.io/crates/equix) backend that produces bundles of
//! difficulty-filtered proofs.  An optional **near-stateless** protocol layer
//! (feature `near-stateless`) adds server/client helpers for challenge
//! issuance, replay protection, and submission verification.
//!
//! # Feature flags
//!
//! | Flag | Default | Description |
//! |------|---------|-------------|
//! | `equix` | off | Enables the [`EquixEngine`] solver and EquiX proof types. |
//! | `near-stateless` | off | Adds the [`near_stateless`] module (implies `equix`). |
//!
//! # Quick start (feature `equix`)
//!
//! ```rust
//! # #[cfg(feature = "equix")]
//! # {
//! use rspow::equix::{EquixEngineBuilder, ProofBundle};
//! use rspow::pow::{PowBundle, PowEngine};
//! use std::sync::atomic::AtomicU64;
//! use std::sync::Arc;
//!
//! let progress = Arc::new(AtomicU64::new(0));
//! let mut engine = EquixEngineBuilder::default()
//!     .bits(1)
//!     .threads(1)
//!     .required_proofs(1)
//!     .progress(progress)
//!     .build_validated()
//!     .expect("valid config");
//!
//! let master = [0xABu8; 32];
//! let bundle = engine.solve_bundle(master).expect("solve succeeds");
//!
//! assert_eq!(bundle.proofs().len(), 1);
//! bundle.verify_strict(1, 1).expect("bundle verifies");
//! # }
//! ```

#![deny(missing_docs)]

/// Error types returned by engine and verification operations.
pub mod error;
/// Generic proof-of-work traits ([`PowConfig`], [`PowProof`], [`PowBundle`],
/// [`PowEngine`]).
pub mod pow;

/// Low-level challenge derivation utilities.
pub mod core;
/// Concurrency primitives for multi-threaded solvers.
pub mod stream;
/// Convenience type aliases used across the crate.
pub mod types;

/// EquiX proof-of-work backend (requires feature `equix`).
#[cfg(feature = "equix")]
pub mod equix;
/// Near-stateless challenge/response protocol helpers (requires feature
/// `near-stateless`).
#[cfg(feature = "near-stateless")]
pub mod near_stateless;

#[cfg(feature = "equix")]
pub use crate::equix::{EquixEngine, EquixEngineBuilder, Proof, ProofBundle, ProofConfig};
pub use crate::error::{Error, VerifyError};
#[cfg(feature = "near-stateless")]
pub use crate::near_stateless::*;
pub use crate::pow::{PowBundle, PowConfig, PowEngine, PowProof};
