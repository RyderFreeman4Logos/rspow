//! EquiX proof-of-work backend.
//!
//! Contains the concrete proof types ([`Proof`], [`ProofBundle`],
//! [`ProofConfig`]) and the multi-threaded [`EquixEngine`] solver.

/// Multi-threaded EquiX solver engine.
pub mod engine;
/// EquiX proof, bundle, and configuration types.
pub mod types;

pub use engine::{EquixEngine, EquixEngineBuilder};
pub use types::{Proof, ProofBundle, ProofConfig};
