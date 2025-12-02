//! 核心工具函数模块
//! Core utilities module
//!
//! 本模块包含用于工作量证明 (PoW) 的核心哈希生成逻辑。
//! 主要是为了确保挑战 (Challenge) 的生成是确定性的且与特定的 Proof ID 绑定。

use blake3::Hasher as Blake3Hasher; // 引入 Blake3 哈希算法的 Hasher 结构体。Blake3 是一种极快且安全的加密哈希函数。

/// 根据主挑战 (Master Challenge) 和证明 ID (Proof ID) 派生出一个特定的子挑战。
///
/// # 目的
/// 在挖掘多个证明时，我们不能对每一个 nonce 使用相同的挑战种子，
/// 否则容易遭受预计算攻击或无法覆盖足够的搜索空间。
/// 此函数通过将 master_challenge 与 proof_id 混合，为每一个 nonce 确保唯一的挑战值。
///
/// # 参数
/// * `master_challenge`: 整个证明包的基础挑战种子 (32字节)。
/// * `proof_id`: 当前尝试的特定证明序号 (nonce)。
///
/// # 返回值
/// * `[u8; 32]`: 派生出的特定挑战哈希。
pub fn derive_challenge(master_challenge: [u8; 32], proof_id: u64) -> [u8; 32] {
    // 初始化一个新的 Blake3 哈希器。
    let mut hasher = Blake3Hasher::new();
    
    // 写入域分隔符 (Domain Separator)。
    // 这是一个安全最佳实践，用于区分不同用途的哈希计算，防止不同上下文下的哈希碰撞。
    // "rspow:equix:challenge:v1|" 明确标识了这是 rspow 库中 equix 算法的挑战生成部分，版本为 v1。
    hasher.update(b"rspow:equix:challenge:v1|");
    
    // 写入主挑战数据。
    hasher.update(&master_challenge);
    
    // 写入证明 ID。
    // 使用 to_le_bytes() (小端序) 确保在不同 CPU 架构上的一致性。
    // 这一点非常重要，否则在大端序机器上生成的哈希将与小端序机器不同。
    hasher.update(&proof_id.to_le_bytes());
    
    // 完成哈希计算并返回结果。
    // into() 将 OutputReader 转换为 [u8; 32] 数组。
    hasher.finalize().into()
}

#[cfg(test)] // 仅在运行测试时编译此模块
mod tests {
    use super::*; // 引入父模块的所有内容

    #[test]
    fn derive_challenge_is_deterministic_and_id_sensitive() {
        // 定义一个测试用的主挑战种子
        let master = [42u8; 32];
        
        // 测试确定性：相同的输入必须产生相同的输出
        let c1 = derive_challenge(master, 0);
        let c2 = derive_challenge(master, 0);
        
        // 测试敏感性：不同的 proof_id 必须产生完全不同的哈希
        let c3 = derive_challenge(master, 1);
        
        assert_eq!(c1, c2, "same input must yield same challenge (相同输入必须产生相同挑战)");
        assert_ne!(c1, c3, "different proof ids should change challenge (不同的证明ID应改变挑战结果)");
    }
}