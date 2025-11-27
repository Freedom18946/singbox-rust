//! sb-runtime: Offline-only handshake alpha (feature-gated)
//!
//! # Global Strategic Logic / 全局战略逻辑
//!
//! This crate serves as the **Deterministic Verification Engine** for the Sing-Box ecosystem.
//! It is designed to validate protocol correctness without the unpredictability of real-world networks.
//!
//! 本 crate 是 Sing-Box 生态系统的 **确定性验证引擎**。
//! 它的设计目标是在没有真实网络不可预测性的情况下验证协议的正确性。
//!
//! ## Core Philosophy / 核心理念
//!
//! 1.  **Offline-First (离线优先)**:
//!     - All tests run in memory or on localhost loopback. No external network dependencies.
//!     - 所有测试都在内存中或本地回环上运行。无外部网络依赖。
//!
//! 2.  **Determinism (确定性)**:
//!     - Given a seed, the handshake sequence, packet sizes, and content shapes are 100% reproducible.
//!     - 给定一个种子 (seed)，握手序列、包大小和内容形状是 100% 可复现的。
//!
//! 3.  **Shape Verification (形状校验)**:
//!     - We verify the *structure* of protocols (headers, lengths, magic bytes) rather than full cryptographic correctness.
//!     - This allows for extremely fast regression testing of protocol state machines.
//!     - 我们验证协议的 *结构*（头部、长度、魔术字节），而不是完整的加密正确性。
//!     - 这允许对协议状态机进行极快的回归测试。
//!
//! ## Strategic Value / 战略价值
//!
//! - **CI/CD Stability**: Provides flaky-free tests for protocol logic.
//! - **Protocol Development**: Rapid prototyping of new protocols without setting up complex environments.
//! - **Chaos Engineering**: Simulates network anomalies (packet loss, reordering) in a controlled manner.
//!
//! - **CI/CD 稳定性**: 为协议逻辑提供无抖动的测试。
//! - **协议开发**: 快速原型开发新协议，无需设置复杂的环境。
//! - **混沌工程**: 以受控方式模拟网络异常（丢包、乱序）。
//!
//! # Feature Flags
//!
//! - `handshake_alpha`: Enables core handshake testing features. / 启用核心握手测试功能。
//! - `io_local_alpha`: Enables local IO testing (depends on `handshake_alpha`). / 启用本地 IO 测试功能（依赖 `handshake_alpha`）。
//!
//! # Example / 示例
//!
//! ```rust,ignore
//! use sb_runtime::prelude::*;
//!
//! // Create protocol context / 创建协议上下文
//! let ctx = ProtoCtx {
//!     host: "example.com".to_string(),
//!     port: 443,
//! };
//!
//! // Use protocol implementation for handshake testing / 使用协议实现进行握手测试
//! // ...
//! ```

#![deny(unused_must_use)]
#![allow(clippy::needless_return)]

// ==================== Feature-gated modules ====================
// 以下模块仅在启用 `handshake_alpha` feature 时暴露

#[cfg(feature = "handshake_alpha")]
pub mod handshake;

#[cfg(feature = "handshake_alpha")]
pub mod jsonl;

#[cfg(feature = "handshake_alpha")]
pub mod loopback;

#[cfg(feature = "handshake_alpha")]
pub mod scenario;

#[cfg(all(feature = "handshake_alpha", feature = "io_local_alpha"))]
pub mod tcp_local;

/// 协议实现模块
///
/// 包含各种协议的测试桩实现
#[cfg(feature = "handshake_alpha")]
pub mod protocols {
    pub mod trojan;
    pub mod vmess;
}

// ==================== Public exports ====================
// 将常用类型直接导出到 crate 根级别，便于使用

#[cfg(feature = "handshake_alpha")]
pub use handshake::*;

#[cfg(feature = "handshake_alpha")]
pub use jsonl::{basic_verify, replay_decode as jsonl_replay_decode, stream_frames};

#[cfg(feature = "handshake_alpha")]
pub use loopback::{
    replay_decode as loopback_replay_decode, run_once, Frame, FrameDir, LoopConn, SessionLog,
    SessionMetrics, XorObfuscator,
};

#[cfg(feature = "handshake_alpha")]
pub use protocols::*;

#[cfg(feature = "handshake_alpha")]
pub use scenario::*;

#[cfg(all(feature = "handshake_alpha", feature = "io_local_alpha"))]
pub use tcp_local::*;

// ==================== Disabled state fallback ====================
// 未启用 alpha 时的占位模块，确保 crate 可编译

/// 占位模块，确保 crate 在未启用 feature 时仍可编译
///
/// 此模块不导出任何公共 API，仅用于避免空 crate 的编译器警告
#[cfg(not(feature = "handshake_alpha"))]
mod disabled {
    /// 空操作函数，仅用于确保模块非空
    ///
    /// 此函数不应被调用，仅作为占位符存在
    #[allow(dead_code)]
    pub(crate) fn _noop() {}
}

// ==================== Prelude module ====================
// 提供便捷的 glob import

/// Prelude 模块，包含常用类型和 trait
///
/// 使用 `use sb_runtime::prelude::*;` 可以一次性导入所有常用类型
///
/// # 示例
///
/// ```rust,ignore
/// use sb_runtime::prelude::*;
/// ```
#[cfg(feature = "handshake_alpha")]
pub mod prelude {
    pub use crate::handshake::*;
    pub use crate::jsonl::{basic_verify, replay_decode as jsonl_replay_decode, stream_frames};
    pub use crate::loopback::{
        replay_decode as loopback_replay_decode, run_once, Frame, FrameDir, LoopConn, SessionLog,
        SessionMetrics, XorObfuscator,
    };
    pub use crate::protocols::*;
    pub use crate::scenario::*;

    #[cfg(feature = "io_local_alpha")]
    pub use crate::tcp_local::*;
}

/// 空 prelude 占位符
///
/// 在未启用 `handshake_alpha` feature 时提供空的 prelude 模块，
/// 防止依赖方的 `use` 语句报错
#[cfg(not(feature = "handshake_alpha"))]
pub mod prelude {}
