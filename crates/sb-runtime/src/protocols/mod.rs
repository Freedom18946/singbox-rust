//! Protocol implementations (offline, alpha)
//!
//! 此模块包含各种协议的测试桩实现，用于离线握手测试。
//!
//! # 可用协议
//! - [`trojan`]: Trojan 协议的测试桩
//! - [`vmess`]: VMess 协议的测试桩

pub mod trojan;
pub mod vmess;

pub use trojan::*;
pub use vmess::*;
