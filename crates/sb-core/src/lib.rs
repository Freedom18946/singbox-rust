pub mod adapter;
pub mod error;
pub mod error_map;
pub mod errors;
pub mod health;
pub mod inbound; // <— 新增导出，供 bridge/scaffold 使用
pub mod log;
pub mod metrics;
pub mod net;
pub mod outbound; // <— 新增导出，供 bridge/scaffold 使用
pub mod routing;
pub mod runtime;
pub mod session;
pub mod socks5;
pub mod telemetry;
pub mod transport;
pub mod types;
pub mod util;
pub mod admin {
    pub mod http;
}
pub mod dns;
pub mod http;

// 别名模块：为兼容性提供简短的模块名
pub mod obs {
    pub use crate::outbound::observe::*;
    // 便于使用的 access 模块别名
    pub mod access {
        pub use crate::outbound::observe::*;
    }
}

pub use adapter::*; // 兼容 re-export
