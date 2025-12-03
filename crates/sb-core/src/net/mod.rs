// 网络层模块汇总：保持对外 API 稳定，**不要**随意改命名空间。
// 任何内部重构，先通过这里的 pub use 做平滑过渡（Never break userspace）。

pub mod metered;
pub mod util;
// 对外暴露 datagram 子模块，满足 sb_adapters 对 Udp* 类型与工具函数的引用。
pub mod datagram;
pub mod dial;
pub mod rate_limit;
pub mod rate_limit_metrics;
pub mod ratelimit;
pub mod tcp_rate_limit;
pub mod udp_upstream_map;
// Enhanced UDP NAT implementation with O(log N) eviction
pub mod udp_nat;
// v2: Generation-based eviction with capacity management
pub mod udp_nat_v2;
// Core UDP NAT system according to design specifications
pub mod udp_nat_core;
// UDP packet processor with NAT integration
pub mod udp_processor;

pub use rate_limit::RateLimiter;

// 兼容老用法：上层普遍 `use crate::net::Address;`
pub use self::util::Address;
