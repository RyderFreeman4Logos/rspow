//! EquiX 重写版核心库
//! EquiX-only rewrite core library.
//!
//! 本库提供了一个基于 EquiX 算法的同步工作量证明 (PoW) 引擎和验证类型。
//! 目标是提供高性能、线程安全且易于集成的 PoW 解决方案。

// 声明子模块
pub mod core;   // 核心工具 (哈希生成等)
pub mod engine; // 核心引擎逻辑 (求解器)
pub mod error;  // 错误类型定义
pub mod stream; // 并发流控制工具
pub mod types;  // 数据结构定义 (Proof, Bundle)

// 重新导出 (Re-export) 常用类型，方便用户直接从 crate 根路径引用
// 这样用户只需要 use crate_name::EquixEngine; 而不需要 use crate_name::engine::EquixEngine;
pub use crate::engine::{EquixEngine, EquixEngineBuilder, PowEngine};
pub use crate::error::{Error, VerifyError};
pub use crate::types::{Proof, ProofBundle, ProofConfig};