//! sb-adapters 的"出站适配器"模块
//!
//! 包含各种协议的出站连接器实现，包括：
//! - VMess 协议连接器
//! - VLESS 协议连接器
//! - TUIC 协议连接器

pub mod tuic;
pub mod vless;
pub mod vmess;

// pub use vmess::{VmessConnector, VmessConfig, VmessCommand};
// pub use vless::{VlessConnector, VlessConfig, VlessCommand};
// pub use tuic::{TuicConnector, TuicConfig, TuicCommand};
