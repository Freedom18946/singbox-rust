//! sb-runtime: offline-only handshake alpha (feature-gated).
//! 非启用特性也必须能通过编译（Never break userspace）。
#![deny(unused_must_use)]
#![allow(clippy::needless_return)]

// 启用 alpha：暴露 trait 与协议桩实现
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

#[cfg(feature = "handshake_alpha")]
pub mod protocols {
    pub mod trojan;
    pub mod vmess;
}
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

// 未启用 alpha：不暴露任何 API，但保证可编译
#[cfg(not(feature = "handshake_alpha"))]
mod disabled {
    // 保留一个空模块以避免"空 crate"引发的奇怪 lint；不导出任何可见符号。
    #[allow(dead_code)]
    pub(crate) fn _noop() {}
}

// 公共前导（仅在 alpha 开启时可用）
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
#[cfg(not(feature = "handshake_alpha"))]
pub mod prelude {} // 空占位，防止依赖方 use 时报错到处扩散；按需 gate 即可。
