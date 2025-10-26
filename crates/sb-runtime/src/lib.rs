//! sb-runtime: Offline-only handshake alpha (feature-gated)
//!
//! 此 crate 提供协议握手的离线测试和验证工具，主要用于：
//! - 协议握手的确定性模拟（基于 seed 的可重现性）
//! - JSONL 格式的会话日志记录和回放
//! - 回环（loopback）连接的测试
//! - 多种协议（Trojan、VMess）的测试桩实现
//!
//! # Feature Flags
//!
//! - `handshake_alpha`: 启用核心握手测试功能
//! - `io_local_alpha`: 启用本地 IO 测试功能（依赖 `handshake_alpha`）
//!
//! # 设计原则
//!
//! - **Never break userspace**: 即使不启用 feature，也必须能通过编译
//! - **确定性**: 所有测试数据生成都是确定性的，便于重现
//! - **离线优先**: 不做真实加密或 IO，仅用于 shape/长度/可复现性校验
//!
//! # 示例
//!
//! ```rust,ignore
//! use sb_runtime::prelude::*;
//!
//! // 创建协议上下文
//! let ctx = ProtoCtx {
//!     host: "example.com".to_string(),
//!     port: 443,
//! };
//!
//! // 使用协议实现进行握手测试
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
