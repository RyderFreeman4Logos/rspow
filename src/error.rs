//! 错误处理模块
//! Error handling module
//!
//! 本文件定义了库中可能出现的错误类型。
//! 良好的错误处理对于库的可用性至关重要，它帮助调用者理解出了什么问题。

use thiserror::Error; // 引入 `thiserror` 库的 `Error` 派生宏，它可以帮助我们轻松定义实现了 standard `std::error::Error` trait 的错误枚举。

/// 验证过程中可能出现的错误。
/// VerifyError defines errors that occur specifically during the verification of a proof.
#[derive(Debug, Clone, PartialEq, Eq, Error)] // 自动派生 Debug, Clone, PartialEq, Eq trait，以及最重要的 Error trait。
pub enum VerifyError {
    /// 当同一个证明包 (ProofBundle) 中包含重复的证明 ID 时返回。
    /// 这是一种防范重放攻击或生成错误的机制。
    #[error("duplicate proof")] // 定义当打印这个错误时的显示文本。
    DuplicateProof,

    /// 当证明的哈希值没有达到配置要求的难度（前导零位数不足）时返回。
    /// 这是工作量证明 (PoW) 验证的核心检查。
    #[error("proof does not meet difficulty")]
    InvalidDifficulty,

    /// 当证明的数据结构被破坏，或者 EquiX 验证失败时返回。
    /// 这通常意味着数据在传输中损坏，或者是无效的解。
    #[error("malformed proof or bundle")]
    Malformed,
}

/// 库的一般性错误。
/// General errors for the library, covering configuration and runtime issues.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum Error {
    /// 当提供的配置参数无效时（例如线程数为 0，或者难度位数不合理）。
    /// String 字段包含具体的错误描述信息。
    #[error("invalid config: {0}")]
    InvalidConfig(String),

    /// 当求解器 (Solver) 运行过程中发生不可恢复的错误时返回。
    /// 比如 EquiX 内部错误。
    #[error("solver failed: {0}")]
    SolverFailed(String),

    /// 当用于线程间通信的通道 (Channel) 被意外关闭时返回。
    /// 这通常意味着工作线程崩溃了或者被提前终止了。
    #[error("solver channel closed")]
    ChannelClosed,
}