//! 并发流控制模块
//! Stream control module
//!
//! 本模块提供了用于多线程环境下的同步原语。
//! 主要用于在多个工作线程之间安全地分配任务 (NonceSource) 和控制停止信号 (StopFlag)。

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering}; // 引入原子类型。原子操作是无锁并发编程的基础。

/// Nonce 生成源。
/// 这是一个线程安全的计数器，用于给不同的工作线程分配不重复的 Proof ID (即 nonce)。
#[derive(Debug)]
pub struct NonceSource {
    // 使用 AtomicU64 保证在多线程并发访问时，计数的增加是原子的，不会出现竞态条件。
    next: AtomicU64,
}

impl NonceSource {
    /// 创建一个新的 NonceSource。
    ///
    /// # 参数
    /// * `start`: 计数的起始值。
    pub const fn new(start: u64) -> Self {
        Self {
            next: AtomicU64::new(start),
        }
    }

    /// 获取下一个可用的 nonce，并将内部计数器加一。
    ///
    /// # 线程安全性
    /// 此方法是线程安全的，可以被多个线程同时调用。
    ///
    /// # 内存顺序 (Memory Ordering)
    /// 这里使用了 `Ordering::Relaxed`。
    /// 解释：我们只关心获取唯一的值，并不依赖这个操作与其他内存操作的严格顺序（比如 happens-before 关系）。
    /// Relaxed 顺序提供了最好的性能，因为它允许 CPU 和编译器对指令进行重排，只要保证原子性即可。
    #[inline] // 建议编译器内联此函数以提高性能，因为这是一个极高频调用的函数。
    pub fn fetch(&self) -> u64 {
        // fetch_add 返回加法*之前*的值，这正是我们想要的当前 nonce。
        self.next.fetch_add(1, Ordering::Relaxed)
    }
}

/// 停止标志。
/// 用于协调多个线程何时应该停止工作。
/// 例如：当所需的证明数量已经凑齐，或者用户取消了任务时。
#[derive(Debug)]
pub struct StopFlag {
    // 使用 AtomicBool 在线程间共享布尔状态。
    stop: AtomicBool,
}

impl StopFlag {
    /// 创建一个新的 StopFlag，初始状态为 false (不停止)。
    pub const fn new() -> Self {
        Self {
            stop: AtomicBool::new(false),
        }
    }

    /// 检查是否应该停止工作。
    ///
    /// 工作线程会在循环中不断检查这个方法。
    #[inline]
    pub fn should_stop(&self) -> bool {
        // 同样使用 Relaxed 顺序，因为稍微延迟一点点看到停止信号通常是可以接受的，
        // 而在紧密循环中检查此标志的性能开销更为关键。
        self.stop.load(Ordering::Relaxed)
    }

    /// 强制设置停止标志为 true。
    ///
    /// 当满足退出条件时调用此方法。
    pub fn force_stop(&self) {
        // 这里使用 SeqCst (Sequentially Consistent) 顺序。
        // 虽然 Relaxed 可能也够用，但 SeqCst 提供了最强的内存保证，
        // 确保这个“停止”写入操作对所有线程立即可见，并充当内存屏障。
        // 因为这是一个低频操作（只在结束时调用一次），所以性能开销可以忽略。
        self.stop.store(true, Ordering::SeqCst);
    }
}

// 为 StopFlag 实现 Default trait，使其可以通过 StopFlag::default() 创建。
impl Default for StopFlag {
    fn default() -> Self {
        Self::new()
    }
}