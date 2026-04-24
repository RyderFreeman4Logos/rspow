use crate::core::derive_challenge;
use crate::error::VerifyError;
use crate::pow::{PowBundle, PowConfig, PowProof};
use blake3::hash as blake3_hash;
use equix as equix_crate;

/// A single EquiX proof-of-work solution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Proof {
    /// Nonce id used to derive the per-proof challenge.
    pub id: u64,
    /// The 32-byte challenge derived from the master challenge and [`id`](Self::id).
    pub challenge: [u8; 32],
    /// The 16-byte EquiX solution whose BLAKE3 hash meets the difficulty target.
    pub solution: [u8; 16],
}

/// Difficulty configuration for an EquiX proof bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProofConfig {
    /// Required number of leading zero bits in the BLAKE3 hash of each solution.
    pub bits: u32,
}

/// An ordered collection of [`Proof`]s sharing a common master challenge.
///
/// # Verification
///
/// Use [`verify_strict`](Self::verify_strict) to check that every proof is
/// valid, unique, sorted, and that the bundle meets a minimum difficulty and
/// proof count.
///
/// ```rust
/// # #[cfg(feature = "equix")]
/// # {
/// use rspow::equix::{EquixEngineBuilder, ProofBundle};
/// use rspow::pow::{PowBundle, PowEngine};
/// use std::sync::atomic::AtomicU64;
/// use std::sync::Arc;
///
/// let progress = Arc::new(AtomicU64::new(0));
/// let mut engine = EquixEngineBuilder::default()
///     .bits(1)
///     .threads(1)
///     .required_proofs(2)
///     .progress(progress)
///     .build_validated()
///     .expect("valid config");
///
/// let bundle = engine.solve_bundle([42u8; 32]).expect("solve");
/// bundle.verify_strict(1, 2).expect("bundle is valid");
/// # }
/// ```
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProofBundle {
    /// The proofs in this bundle, sorted by [`Proof::id`].
    pub proofs: Vec<Proof>,
    /// The difficulty configuration shared by all proofs.
    pub config: ProofConfig,
    /// The master challenge from which per-proof challenges are derived.
    pub master_challenge: [u8; 32],
}

impl PowProof for Proof {
    fn id(&self) -> u64 {
        self.id
    }
}

impl PowConfig for ProofConfig {
    fn difficulty(&self) -> u32 {
        self.bits
    }
}

impl PowBundle for ProofBundle {
    type Proof = Proof;
    type Config = ProofConfig;

    fn proofs(&self) -> &[Self::Proof] {
        &self.proofs
    }

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn master_challenge(&self) -> &[u8; 32] {
        &self.master_challenge
    }

    fn insert_proof(&mut self, proof: Self::Proof) -> Result<(), VerifyError> {
        ProofBundle::insert_proof(self, proof)
    }

    fn verify_strict(
        &self,
        min_difficulty: u32,
        min_required_proofs: usize,
    ) -> Result<(), VerifyError> {
        ProofBundle::verify_strict(self, min_difficulty, min_required_proofs)
    }
}

impl ProofBundle {
    /// Return the number of proofs in this bundle.
    pub fn len(&self) -> usize {
        self.proofs.len()
    }

    /// Return `true` if the bundle contains no proofs.
    pub fn is_empty(&self) -> bool {
        self.proofs.is_empty()
    }

    /// Insert a proof, maintaining sorted order by id.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError::DuplicateProof`] if a proof with the same id
    /// already exists.
    pub fn insert_proof(&mut self, proof: Proof) -> Result<(), VerifyError> {
        if self.proofs.iter().any(|p| p.id == proof.id) {
            return Err(VerifyError::DuplicateProof);
        }
        self.proofs.push(proof);
        self.proofs.sort_by_key(|p| p.id);
        Ok(())
    }

    /// Verify every proof in the bundle and enforce structural invariants.
    ///
    /// Checks that the bundle has at least `min_required_proofs` proofs, that
    /// the configured difficulty is at least `min_difficulty`, that proofs are
    /// sorted by id with no duplicates, and that each individual proof passes
    /// EquiX and difficulty verification.
    ///
    /// # Errors
    ///
    /// Returns a [`VerifyError`] describing the first violation found.
    pub fn verify_strict(
        &self,
        min_difficulty: u32,
        min_required_proofs: usize,
    ) -> Result<(), VerifyError> {
        if self.proofs.len() < min_required_proofs {
            return Err(VerifyError::InvalidDifficulty);
        }
        if self.config.bits < min_difficulty {
            return Err(VerifyError::InvalidDifficulty);
        }

        let mut prev_id: Option<u64> = None;
        for proof in &self.proofs {
            if let Some(pid) = prev_id {
                if proof.id == pid {
                    return Err(VerifyError::DuplicateProof);
                }
                if proof.id < pid {
                    return Err(VerifyError::Malformed);
                }
            }
            prev_id = Some(proof.id);
            proof.verify(self.config.bits, self.master_challenge)?;
        }
        Ok(())
    }
}

impl Proof {
    /// Verify this proof against the given difficulty and master challenge.
    ///
    /// Checks that the challenge was correctly derived, that the BLAKE3 hash
    /// of the solution has at least `bits` leading zero bits, and that the
    /// EquiX puzzle is satisfied.
    ///
    /// # Errors
    ///
    /// Returns [`VerifyError::Malformed`] if the challenge or EquiX solution
    /// is invalid, or [`VerifyError::InvalidDifficulty`] if the hash does not
    /// meet the target.
    pub fn verify(&self, bits: u32, master_challenge: [u8; 32]) -> Result<(), VerifyError> {
        let expected_challenge = derive_challenge(master_challenge, self.id);
        if expected_challenge != self.challenge {
            return Err(VerifyError::Malformed);
        }

        let hash = blake3_hash(&self.solution);
        let hash_bytes: [u8; 32] = *hash.as_bytes();
        let leading = leading_zero_bits(&hash_bytes);
        if leading < bits {
            return Err(VerifyError::InvalidDifficulty);
        }

        let equix = equix_crate::EquiX::new(&self.challenge).map_err(|_| VerifyError::Malformed)?;
        let solution = equix_crate::Solution::try_from_bytes(&self.solution)
            .map_err(|_| VerifyError::Malformed)?;
        equix
            .verify(&solution)
            .map_err(|_| VerifyError::Malformed)?;

        Ok(())
    }
}

fn leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut count = 0u32;
    for byte in hash {
        if *byte == 0 {
            count += 8;
            continue;
        }
        count += (*byte).leading_zeros();
        break;
    }
    count
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::equix::EquixEngineBuilder;
    use crate::error::VerifyError;
    use crate::pow::PowEngine;
    use std::sync::atomic::AtomicU64;
    use std::sync::Arc;

    fn small_bundle(bits: u32, required: usize) -> ProofBundle {
        let progress = Arc::new(AtomicU64::new(0));
        let mut engine = EquixEngineBuilder::default()
            .bits(bits)
            .threads(1)
            .required_proofs(required)
            .progress(progress)
            .build()
            .expect("build engine");
        let master = [5u8; 32];
        engine.solve_bundle(master).expect("solve bundle")
    }

    #[test]
    fn verify_strict_accepts_valid_bundle() {
        let bundle = small_bundle(1, 2);
        bundle.verify_strict(1, 2).expect("bundle should verify");
    }

    #[test]
    fn verify_strict_rejects_duplicate_id() {
        let base = small_bundle(1, 2);
        let first = base.proofs[0];
        let bundle = ProofBundle {
            proofs: vec![first, first],
            config: base.config,
            master_challenge: base.master_challenge,
        };
        let err = bundle
            .verify_strict(1, 2)
            .expect_err("duplicate id should be rejected");
        assert!(matches!(err, VerifyError::DuplicateProof));
    }

    #[test]
    fn verify_strict_rejects_tampered_challenge() {
        let mut bundle = small_bundle(1, 1);
        bundle.proofs[0].challenge[0] ^= 1;
        let err = bundle
            .verify_strict(1, 1)
            .expect_err("tampered challenge should be rejected");
        assert!(matches!(err, VerifyError::Malformed));
    }
}
