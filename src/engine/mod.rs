//! 核心引擎模块
//! Core engine module
//!
//! 本模块实现了主要的 EquiX 工作量证明引擎 (EquixEngine)。
//! 它负责协调多线程求解、管理任务分配以及处理恢复逻辑。

use crate::core::derive_challenge;
use crate::error::Error;
use crate::stream::{NonceSource, StopFlag};
use crate::types::{Proof, ProofBundle, ProofConfig};
use blake3::hash as blake3_hash;
use derive_builder::Builder; // 使用 Builder 模式宏，简化复杂结构体的构建
use equix as equix_crate;
use flume::{Receiver, Sender, TrySendError}; // 高性能的多生产者多消费者通道
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;

/// PoW 引擎特征 (Trait)。
/// 定义了所有 PoW 引擎必须实现的标准接口。
pub trait PowEngine {
    /// 解决一个新的证明包。
    /// 给定主挑战，从头开始计算所需的证明。
    fn solve_bundle(&mut self, master_challenge: [u8; 32]) -> Result<ProofBundle, Error>;
    
    /// 恢复一个已有的证明包。
    /// 在已有的证明基础上继续计算，直到达到新的 required_proofs 数量。
    fn resume(
        &mut self,
        existing: ProofBundle,
        required_proofs: usize,
    ) -> Result<ProofBundle, Error>;
}

/// EquiX 算法引擎结构体。
///
/// 使用 `derive_builder` 自动生成 Builder 模式代码，
/// 允许用户以流畅的方式配置参数 (例如 `.bits(4).threads(8).build()`).
#[derive(Builder, Debug)]
#[builder(pattern = "owned")] // Builder 消费自身所有权，返回构建好的对象
pub struct EquixEngine {
    /// 目标难度：哈希所需的前导零位数。
    pub bits: u32,
    
    /// 并行计算使用的线程数。
    pub threads: usize,
    
    /// 需要生成的证明总数。
    pub required_proofs: usize,
    
    /// 进度计数器 (原子操作)。
    /// 用于向外部报告当前已找到的证明数量。
    pub progress: Arc<AtomicU64>,
}

/// 证明结果类型别名，方便书写。
type ProofResult = Result<Proof, Error>;

/// 求解器函数类型别名。
/// 这是一个闭包或函数指针，接受挑战和难度，返回可能的解。
/// `Send + Sync` 标记是必须的，因为它将在多线程间共享。
type Solver = dyn Fn([u8; 32], u32) -> Result<Option<[u8; 16]>, Error> + Send + Sync;

impl EquixEngine {
    /// 验证引擎配置参数的有效性。
    fn validate(&self) -> Result<(), Error> {
        if self.bits == 0 {
            return Err(Error::InvalidConfig("bits must be > 0".into()));
        }
        if self.threads == 0 {
            return Err(Error::InvalidConfig("threads must be >= 1".into()));
        }
        if self.required_proofs == 0 {
            return Err(Error::InvalidConfig("required_proofs must be >= 1".into()));
        }
        Ok(())
    }
}

// 扩展自动生成的 Builder，添加额外的验证逻辑
impl EquixEngineBuilder {
    /// 验证构建器中的参数。
    /// 处理 Option 类型，因为在 build 之前某些字段可能未设置。
    fn validate(&self) -> Result<(), Error> {
        if self.bits.unwrap_or(0) == 0 {
            return Err(Error::InvalidConfig("bits must be > 0".into()));
        }
        if self.threads.unwrap_or(0) == 0 {
            return Err(Error::InvalidConfig("threads must be >= 1".into()));
        }
        if self.required_proofs.unwrap_or(0) == 0 {
            return Err(Error::InvalidConfig("required_proofs must be >= 1".into()));
        }
        if self.progress.is_none() {
            return Err(Error::InvalidConfig("progress must be provided".into()));
        }
        Ok(())
    }

    /// 构建并验证引擎实例。
    /// 相比默认的 `build()`，这个方法提供了更友好的错误处理。
    pub fn build_validated(self) -> Result<EquixEngine, Error> {
        self.validate()?;
        self.build()
            .map_err(|e| Error::InvalidConfig(e.to_string()))
    }
}

impl PowEngine for EquixEngine {
    /// 实现 `solve_bundle`：从零开始生成证明包。
    fn solve_bundle(&mut self, master_challenge: [u8; 32]) -> Result<ProofBundle, Error> {
        self.validate()?;
        
        // 重置进度计数器
        self.progress.store(0, Ordering::SeqCst);
        
        let mut bundle = ProofBundle {
            proofs: Vec::new(),
            config: ProofConfig { bits: self.bits },
            master_challenge,
        };

        // 调用核心求解逻辑 solve_range
        // 从 nonce 0 开始，当前已有 0 个证明，目标是 self.required_proofs
        let new_proofs = solve_range(
            master_challenge,
            self.bits,
            self.threads,
            0, // start_nonce
            0, // current_len
            self.required_proofs,
            self.progress.clone(),
        )?;

        // 将找到的证明插入 bundle
        for proof in new_proofs {
            bundle
                .insert_proof(proof)
                .map_err(|err| Error::SolverFailed(err.to_string()))?;
        }

        Ok(bundle)
    }

    /// 实现 `resume`：在现有证明包基础上继续计算。
    fn resume(
        &mut self,
        mut existing: ProofBundle,
        required_proofs: usize,
    ) -> Result<ProofBundle, Error> {
        self.validate()?;
        
        // 检查配置一致性：继续挖掘的难度必须与原包一致
        if existing.config.bits != self.bits {
            return Err(Error::InvalidConfig(
                "bundle difficulty does not match engine".into(),
            ));
        }
        
        // 验证现有包的有效性，防止基于坏数据继续工作
        existing
            .verify_strict()
            .map_err(|e| Error::SolverFailed(e.to_string()))?;
            
        // 检查目标数量是否合理
        if required_proofs < existing.len() {
            return Err(Error::InvalidConfig(
                "required_proofs must be >= existing proofs".into(),
            ));
        }
        
        // 更新引擎的目标和进度
        self.required_proofs = required_proofs;
        self.progress.store(existing.len() as u64, Ordering::SeqCst);
        
        // 如果已经满足要求，直接返回
        if existing.len() >= required_proofs {
            return Ok(existing);
        }
        
        // 计算起始 nonce：
        // 为了避免重复工作，我们查找现有证明中最大的 ID，从它 + 1 开始。
        // 如果没有证明，则从现有的数量开始（这是一个启发式选择，只要不重复即可）。
        let start_nonce = existing
            .proofs
            .iter()
            .map(|p| p.id)
            .max()
            .map(|m| m.saturating_add(1))
            .unwrap_or(existing.len() as u64);
            
        // 调用核心求解逻辑
        let new_proofs = solve_range(
            existing.master_challenge,
            self.bits,
            self.threads,
            start_nonce,
            existing.len(),
            required_proofs,
            self.progress.clone(),
        )?;

        // 合并新证明
        for proof in new_proofs {
            existing
                .insert_proof(proof)
                .map_err(|err| Error::SolverFailed(err.to_string()))?;
        }
        Ok(existing)
    }
}

/// 辅助函数：使用默认的 `solve_single` 求解器启动范围求解。
#[allow(clippy::too_many_arguments)]
fn solve_range(
    master_challenge: [u8; 32],
    bits: u32,
    threads: usize,
    start_nonce: u64,
    current_len: usize,
    target_total: usize,
    progress: Arc<AtomicU64>,
) -> Result<Vec<Proof>, Error> {
    solve_range_with(
        master_challenge,
        bits,
        threads,
        start_nonce,
        current_len,
        target_total,
        progress,
        // 将 solve_single 函数包装为 Arc 共享闭包
        Arc::new(solve_single as fn([u8; 32], u32) -> Result<Option<[u8; 16]>, Error>),
    )
}

/// 核心并行求解逻辑。
///
/// 架构：Master-Worker 模式 (或者说生产者-消费者模式的变体)
/// - 主线程：负责收集结果，监控进度，并在完成时通知所有线程停止。
/// - Worker线程：并行地从 NonceSource 获取 ID，计算，并发送结果回主线程。
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn solve_range_with(
    master_challenge: [u8; 32],
    bits: u32,
    threads: usize,
    start_nonce: u64,
    current_len: usize,
    target_total: usize,
    progress: Arc<AtomicU64>,
    solver: Arc<Solver>,
) -> Result<Vec<Proof>, Error> {
    // 再次检查目标数量
    if current_len > target_total {
        return Err(Error::InvalidConfig(
            "current proof count exceeds required proofs".into(),
        ));
    }

    let needed = target_total.saturating_sub(current_len);
    if needed == 0 {
        return Ok(Vec::new());
    }

    // 初始化并发原语
    let nonce_source = Arc::new(NonceSource::new(start_nonce));
    let stop = Arc::new(StopFlag::new());
    
    // 创建通信通道 (Channel)
    // 缓冲区大小设为线程数的 2 倍，既保证吞吐量又防止内存积压
    let bound = (threads.max(1) * 2).max(1);
    let (tx, rx): (Sender<ProofResult>, Receiver<ProofResult>) = flume::bounded(bound);
    
    let mut joins = Vec::with_capacity(threads.max(1));

    // 启动 Worker 线程
    for _ in 0..threads.max(1) {
        let worker_nonce = nonce_source.clone();
        let worker_stop = stop.clone();
        let worker_tx = tx.clone();
        let worker_solver = solver.clone();
        
        let join = thread::spawn(move || {
            worker_loop(
                master_challenge,
                bits,
                worker_nonce,
                worker_stop,
                worker_tx,
                worker_solver,
            );
        });
        joins.push(join);
    }
    
    // 必须丢弃主线程持有的发送端 (tx)，否则如果所有 worker 都退出了，
    // 接收端 (rx) 永远不会知道通道已关闭 (EOF)，导致死锁。
    drop(tx);

    let mut proofs = Vec::with_capacity(needed);
    let mut seen = HashSet::with_capacity(needed * 2 + 1);

    // 主循环：收集结果
    while proofs.len() < needed {
        match rx.recv() {
            Ok(Ok(proof)) => {
                // 收到成功证明
                // 去重检查 (尽管 NonceSource 保证了 ID 唯一，但作为防御性编程)
                if !seen.insert(proof.id) {
                    continue;
                }
                proofs.push(proof);
                
                // 更新进度
                let current = progress.fetch_add(1, Ordering::SeqCst) + 1;
                
                // 如果已达到目标，向所有线程发出停止信号
                if current >= target_total as u64 {
                    stop.force_stop();
                }
            }
            Ok(Err(err)) => {
                // 收到 Worker 报错 (例如 EquiX 内部错误)
                // 立即停止所有工作并返回错误
                stop.force_stop();
                join_handles(joins);
                return Err(err);
            }
            Err(_) => {
                // 通道已关闭 (所有发送端都 drop 了)
                // 这通常意味着所有 worker 都意外退出了，停止循环。
                break;
            }
        }
    }

    // 清理工作：确保所有线程都已退出
    stop.force_stop();
    join_handles(joins);

    // 最终检查：是否收集到了足够的证明？
    if proofs.len() < needed {
        return Err(Error::ChannelClosed);
    }

    // 结果排序
    proofs.sort_by_key(|p| p.id);
    Ok(proofs)
}

/// Worker 线程的主循环。
/// 不断获取 nonce，计算，发送结果，直到收到停止信号。
fn worker_loop(
    master_challenge: [u8; 32],
    bits: u32,
    nonce_source: Arc<NonceSource>,
    stop: Arc<StopFlag>,
    tx: Sender<ProofResult>,
    solver: Arc<Solver>,
) {
    while !stop.should_stop() {
        // 1. 获取任务 (Nonce)
        let id = nonce_source.fetch();
        
        // 2. 准备上下文
        let challenge = derive_challenge(master_challenge, id);
        
        // 3. 执行求解
        match solver(challenge, bits) {
            Ok(Some(solution)) => {
                // 找到解了！构建 Proof 对象
                let proof = Proof {
                    id,
                    challenge,
                    solution,
                };
                
                // 尝试发送结果
                match tx.try_send(Ok(proof)) {
                    Ok(()) => {} // 发送成功
                    Err(TrySendError::Full(_)) => {
                        // 通道已满。
                        // 在这种情况下，我们选择丢弃这个解而不是阻塞。
                        // 为什么？因为这是一种背压 (Backpressure) 机制。
                        // 如果主线程处理不过来，worker 应该减速或者丢弃工作，而不是耗尽内存。
                        // 注意：这可能会导致通过 `id` 顺序产生空洞，但对于 PoW 来说是可以接受的。
                    }
                    Err(TrySendError::Disconnected(_)) => {
                        // 接收端已关闭，说明主线程可能已经退出了。
                        stop.force_stop();
                        break;
                    }
                }
            }
            Ok(None) => {
                // 此 nonce 没有解，继续下一个。
                continue;
            }
            Err(err) => {
                // 发生严重错误，发送错误信息并通知停止。
                let _ = tx.send(Err(err));
                stop.force_stop();
                break;
            }
        }
    }
}

/// 等待所有线程结束 (Join)。
fn join_handles(joins: Vec<thread::JoinHandle<()>>) {
    for handle in joins {
        let _ = handle.join();
    }
}

/// 单次求解函数。
/// 执行 EquiX 求解并检查难度。
fn solve_single(challenge: [u8; 32], bits: u32) -> Result<Option<[u8; 16]>, Error> {
    // 初始化 EquiX 实例
    let equix =
        equix_crate::EquiX::new(&challenge).map_err(|err| Error::SolverFailed(err.to_string()))?;
    
    // 求解 EquiX 难题
    let solutions = equix.solve();
    
    // 遍历所有可能的 EquiX 解
    for sol in solutions.iter() {
        let bytes = sol.to_bytes();
        
        // 计算解的哈希
        let hash = blake3_hash(&bytes);
        let hash: [u8; 32] = *hash.as_bytes();
        
        // 检查哈希难度 (前导零)
        if leading_zero_bits(&hash) >= bits {
            return Ok(Some(bytes));
        }
    }
    // 所有解都不满足难度要求
    Ok(None)
}

// 复用 types 模块中的 leading_zero_bits 逻辑
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
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    #[test]
    fn solve_single_returns_none_when_no_solution_meets_bits() {
        // 测试：当难度极高时 (128 bits)，应该找不到解
        let challenge = [0u8; 32];
        let result = solve_single(challenge, 128).expect("solver should not error");
        assert!(result.is_none());
    }

    #[test]
    fn worker_skips_challenges_without_solutions() {
        // 测试：Worker 能够正确处理“无解”的情况并继续尝试下一个
        let progress = Arc::new(AtomicU64::new(0));
        let attempts = Arc::new(AtomicUsize::new(0));
        
        // 模拟求解器：前两次尝试返回无解，第三次返回解
        let solver: Arc<Solver> = {
            let attempts = attempts.clone();
            Arc::new(move |_challenge: [u8; 32], _bits: u32| {
                let n = attempts.fetch_add(1, Ordering::SeqCst);
                if n < 2 {
                    Ok(None)
                } else {
                    Ok(Some([n as u8; 16]))
                }
            })
        };

        let proofs = solve_range_with([1u8; 32], 0, 2, 0, 0, 3, progress.clone(), solver)
            .expect("solver should complete");

        assert_eq!(proofs.len(), 3);
        // 验证确实尝试了足够的次数
        assert!(
            attempts.load(Ordering::SeqCst) >= 2,
            "should have skipped at least two attempts"
        );
        assert_eq!(progress.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn solve_bundle_is_deterministic_single_thread() {
        // 测试：单线程下的结果必须是确定性的 (每次运行结果一样)
        let master = [11u8; 32];

        let progress1 = Arc::new(AtomicU64::new(0));
        let mut engine1 = EquixEngineBuilder::default()
            .bits(1)
            .threads(1)
            .required_proofs(3)
            .progress(progress1)
            .build()
            .expect("build engine1");
        let bundle1 = engine1
            .solve_bundle(master)
            .expect("first solve should succeed");

        let progress2 = Arc::new(AtomicU64::new(0));
        let mut engine2 = EquixEngineBuilder::default()
            .bits(1)
            .threads(1)
            .required_proofs(3)
            .progress(progress2)
            .build()
            .expect("build engine2");
        let bundle2 = engine2
            .solve_bundle(master)
            .expect("second solve should succeed");

        assert_eq!(bundle1, bundle2);
    }

    #[test]
    fn resume_starts_from_next_nonce() {
        // 测试：resume 功能是否正确地从已有的最大 ID 继续
        let progress = Arc::new(AtomicU64::new(0));
        let master = [7u8; 32];

        // 构造一个已有的包，起始 nonce 为 5
        let existing_proofs =
            solve_range(master, 1, 1, 5, 0, 1, progress.clone()).expect("seed bundle");

        let bundle = ProofBundle {
            proofs: existing_proofs,
            config: ProofConfig { bits: 1 },
            master_challenge: master,
        };

        // Resume 应该从 5 之后开始，不应重复 5
        let mut engine = EquixEngineBuilder::default()
            .bits(1)
            .threads(1)
            .required_proofs(2)
            .progress(progress.clone())
            .build()
            .expect("build engine");

        let resumed = engine.resume(bundle, 2).expect("resume should succeed");

        assert_eq!(resumed.len(), 2);
        assert!(resumed.proofs.iter().any(|p| p.id == 5));
        assert!(resumed.proofs.iter().any(|p| p.id >= 6));
    }

    #[test]
    fn single_and_multi_thread_solutions_are_equivalent() {
        // 测试：多线程和单线程产生的结果在验证上是等效的（虽然顺序可能不同，但在 ProofBundle 里是排序的）
        let master = [21u8; 32];
        let required = 3usize;

        let progress_single = Arc::new(AtomicU64::new(0));
        let mut engine_single = EquixEngineBuilder::default()
            .bits(1)
            .threads(1)
            .required_proofs(required)
            .progress(progress_single)
            .build()
            .expect("build single-thread engine");

        let bundle_single = engine_single
            .solve_bundle(master)
            .expect("single-thread solve should succeed");

        let progress_multi = Arc::new(AtomicU64::new(0));
        let mut engine_multi = EquixEngineBuilder::default()
            .bits(1)
            .threads(2)
            .required_proofs(required)
            .progress(progress_multi)
            .build()
            .expect("build multi-thread engine");

        let bundle_multi = engine_multi
            .solve_bundle(master)
            .expect("multi-thread solve should succeed");

        assert_eq!(bundle_single.len(), required);
        assert_eq!(bundle_multi.len(), required);
        bundle_single
            .verify_strict()
            .expect("single-thread bundle should verify");
        bundle_multi
            .verify_strict()
            .expect("multi-thread bundle should verify");
        assert_eq!(bundle_single.master_challenge, master);
        assert_eq!(bundle_multi.master_challenge, master);
    }

    #[test]
    fn resume_extends_bundle_n_to_n_plus_m() {
        // 测试：从 N 个扩展到 N+M 个证明
        let master = [31u8; 32];
        let progress = Arc::new(AtomicU64::new(0));
        let mut engine = EquixEngineBuilder::default()
            .bits(1)
            .threads(2)
            .required_proofs(2)
            .progress(progress.clone())
            .build()
            .expect("build engine");

        let initial = engine
            .solve_bundle(master)
            .expect("initial solve should succeed");
        assert_eq!(initial.len(), 2);
        initial
            .verify_strict()
            .expect("initial bundle should verify");

        let resumed = engine
            .resume(initial.clone(), 5)
            .expect("resume should extend bundle");
        assert_eq!(resumed.len(), 5);
        resumed
            .verify_strict()
            .expect("resumed bundle should verify");
        assert!(resumed.proofs.len() > initial.proofs.len());
    }

    #[test]
    fn resume_rejects_mismatched_bits() {
        // 测试：如果难度配置不匹配，Resume 应该报错
        let progress = Arc::new(AtomicU64::new(0));
        let mut engine_high = EquixEngineBuilder::default()
            .bits(2)
            .threads(1)
            .required_proofs(1)
            .progress(progress.clone())
            .build()
            .expect("build high bits engine");

        let bundle = engine_high
            .solve_bundle([9u8; 32])
            .expect("solve initial bundle");

        // 使用低难度配置尝试 resume 高难度的包 -> 拒绝
        let mut engine_low = EquixEngineBuilder::default()
            .bits(1)
            .threads(1)
            .required_proofs(2)
            .progress(Arc::new(AtomicU64::new(0)))
            .build()
            .expect("build low bits engine");

        let err = engine_low
            .resume(bundle, 2)
            .expect_err("should reject bits mismatch");
        assert!(matches!(err, Error::InvalidConfig(_)));
    }
}