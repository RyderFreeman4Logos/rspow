//! 类型定义模块
//! Types definition module
//!
//! 本模块定义了核心的数据结构，包括单个证明 (Proof)、证明配置 (ProofConfig) 和证明包 (ProofBundle)。
//! 同时还包含了核心的验证逻辑 (Verification Logic)。

use crate::core::derive_challenge; // 引入挑战生成函数
use crate::error::VerifyError; // 引入验证错误枚举
use blake3::hash as blake3_hash; // 引入 blake3 哈希函数
use equix as equix_crate; // 引入底层的 equix 库

/// 单个工作量证明结构体。
/// Represents a single unit of proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Proof {
    /// 证明的唯一标识符 (nonce)。
    /// 这是一个不断递增的数字，用于尝试生成满足条件的哈希。
    pub id: u64,

    /// 用于生成此证明的挑战哈希 (32字节)。
    /// 这是通过 `derive_challenge(master_challenge, id)` 计算得出的。
    pub challenge: [u8; 32],

    /// EquiX 算法求解得到的解 (16字节)。
    /// 它是通过解决 EquiX 难题得到的。
    pub solution: [u8; 16],
}

/// 证明配置结构体。
/// Configuration for the proof requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProofConfig {
    /// 难度要求：哈希值必须拥有的前导零的位数 (bits)。
    /// 值越大，找到符合条件的解就越困难。
    pub bits: u32,
}

/// 证明包结构体。
/// A bundle containing multiple proofs and their metadata.
/// 这种结构允许一次性提交和验证多个证明。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ProofBundle {
    /// 包含的证明列表。
    pub proofs: Vec<Proof>,
    
    /// 这些证明所遵循的配置 (难度)。
    pub config: ProofConfig,
    
    /// 生成这些证明所基于的主挑战种子。
    pub master_challenge: [u8; 32],
}

impl ProofBundle {
    /// 返回包中证明的数量。
    pub fn len(&self) -> usize {
        self.proofs.len()
    }

    /// 检查包是否为空。
    pub fn is_empty(&self) -> bool {
        self.proofs.is_empty()
    }

    /// 向包中插入一个新的证明。
    ///
    /// # 逻辑
    /// 1. 检查是否存在重复 ID 的证明，如果存在则拒绝 (防止重复提交)。
    /// 2. 插入证明。
    /// 3. 按 ID 排序证明列表。这对于后续的快速验证和去重非常重要。
    pub fn insert_proof(&mut self, proof: Proof) -> Result<(), VerifyError> {
        // 使用迭代器检查 id 是否已存在
        if self.proofs.iter().any(|p| p.id == proof.id) {
            return Err(VerifyError::DuplicateProof);
        }
        self.proofs.push(proof);
        // 保持有序状态
        self.proofs.sort_by_key(|p| p.id);
        Ok(())
    }

    /// 严格验证整个证明包。
    ///
    /// # 验证步骤
    /// 1. **顺序与唯一性检查**：由于我们在插入时进行了排序，这里确保证明 ID 是严格递增的。
    ///    这不仅检查了唯一性，也确保了列表的有序性。
    /// 2. **单个证明验证**：对列表中的每个证明调用 `verify`。
    pub fn verify_strict(&self) -> Result<(), VerifyError> {
        let mut prev_id: Option<u64> = None;
        for proof in &self.proofs {
            if let Some(pid) = prev_id {
                // 如果当前 ID 等于上一个 ID，说明有重复。
                if proof.id == pid {
                    return Err(VerifyError::DuplicateProof);
                }
                // 如果当前 ID 小于上一个 ID，说明列表未排序，视为畸形数据。
                if proof.id < pid {
                    return Err(VerifyError::Malformed);
                }
            }
            prev_id = Some(proof.id);
            
            // 验证单个证明的有效性
            proof.verify(self.config.bits, self.master_challenge)?;
        }
        Ok(())
    }
}

impl Proof {
    /// 验证单个证明的有效性。
    ///
    /// # 参数
    /// * `bits`: 要求的难度（前导零位数）。
    /// * `master_challenge`: 主挑战种子。
    ///
    /// # 验证流程 (核心逻辑)
    /// 1. **挑战重构**：使用 `master_challenge` 和 `self.id` 重新计算预期的 `challenge`。
    ///    如果计算结果与结构体中存储的 `challenge` 不符，说明数据被篡改。
    /// 2. **EquiX 验证**：使用 `challenge` 初始化 EquiX 验证器，并验证 `solution` 是否是该挑战的有效解。
    ///    这是 "Memory-Hard" (内存困难) 部分的验证，证明求解者确实进行了计算。
    /// 3. **难度验证 (PoW)**：计算 `solution` 的哈希值，并检查其前导零数量是否满足 `bits` 要求。
    ///    这是传统的 PoW 难度检查。
    pub fn verify(&self, bits: u32, master_challenge: [u8; 32]) -> Result<(), VerifyError> {
        // 1. 验证挑战生成的一致性
        let expected_challenge = derive_challenge(master_challenge, self.id);
        if expected_challenge != self.challenge {
            return Err(VerifyError::Malformed);
        }

        // 2. 验证 EquiX 解的有效性
        // EquiX::new 可能会失败 (虽然对于任意 byte 数组通常都能成功，但这是一种防御性编程)
        let equix = equix_crate::EquiX::new(&self.challenge).map_err(|_| VerifyError::Malformed)?;
        
        // 尝试从字节还原 Solution 对象
        let solution = equix_crate::Solution::try_from_bytes(&self.solution)
            .map_err(|_| VerifyError::Malformed)?;
            
        // 执行 EquiX 验证逻辑
        equix
            .verify(&solution)
            .map_err(|_| VerifyError::Malformed)?;

        // 3. 验证哈希难度
        // 计算解的 Blake3 哈希
        let hash = blake3_hash(&self.solution);
        let hash_bytes: [u8; 32] = *hash.as_bytes();
        
        // 计算前导零位数
        let leading = leading_zero_bits(&hash_bytes);
        
        // 检查是否达到目标难度
        if leading < bits {
            return Err(VerifyError::InvalidDifficulty);
        }

        Ok(())
    }
}

/// 辅助函数：计算字节数组的前导零位数。
///
/// # 算法
/// 逐字节检查：
/// - 如果字节是 0，说明这一字节贡献了 8 个零位，继续检查下一个字节。
/// - 如果字节非 0，计算该字节的前导零 (leading_zeros)，累加后返回总数。
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
    use crate::engine::{EquixEngineBuilder, PowEngine};
    use crate::error::VerifyError;
    use std::sync::atomic::AtomicU64;
    use std::sync::Arc;

    // 辅助函数：生成一个包含少量证明的有效 Bundle
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
        // 测试：有效的包应该通过验证
        let bundle = small_bundle(1, 2);
        bundle.verify_strict().expect("bundle should verify");
    }

    #[test]
    fn verify_strict_rejects_duplicate_id() {
        // 测试：包含重复证明 ID 的包应该被拒绝
        let base = small_bundle(1, 2);
        let first = base.proofs[0];
        let bundle = ProofBundle {
            proofs: vec![first, first], // 故意放入重复的 proof
            config: base.config,
            master_challenge: base.master_challenge,
        };
        let err = bundle
            .verify_strict()
            .expect_err("duplicate id should be rejected");
        assert!(matches!(err, VerifyError::DuplicateProof));
    }

    #[test]
    fn verify_strict_rejects_tampered_challenge() {
        // 测试：被篡改挑战数据的证明应该被拒绝
        let mut bundle = small_bundle(1, 1);
        bundle.proofs[0].challenge[0] ^= 1; // 翻转第一字节的一位
        let err = bundle
            .verify_strict()
            .expect_err("tampered challenge should be rejected");
        assert!(matches!(err, VerifyError::Malformed));
    }
}