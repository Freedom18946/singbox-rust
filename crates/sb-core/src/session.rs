//! Connection session tracking and context
//! 连接会话跟踪和上下文
//!
//! # Global Strategic Logic / 全局战略逻辑
//! This module defines the **Context** that flows through the routing pipeline.
//! 本模块定义了流经路由管道的 **上下文**。
//!
//! ## Strategic Role / 战略角色
//! - **Metadata Carrier / 元数据载体**: Carries all necessary information (Source, Destination, User, Sniffed Host) to make routing decisions.
//!   携带做出路由决策所需的所有必要信息（源、目的、用户、嗅探的主机）。

use crate::net::Address;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub enum Transport {
    Tcp,
    Udp,
    Other,
}

/// Parameters for establishing a connection
/// 建立连接的参数
///
/// # Strategic Importance / 战略重要性
/// This struct is the "Packet Header" of the internal application layer. It decouples the routing logic from the underlying transport.
/// 本结构体是内部应用层的“数据包头”。它将路由逻辑与底层传输解耦。
#[derive(Debug, Clone)]
pub struct ConnectParams {
    pub target: Address,
    /// Optional: Source inbound tag (e.g., "tun" / specific instance name)
    /// 可选：来源入站标识（如 "tun" / 具体实例名）
    pub inbound: Option<String>,
    /// Optional: User tag (participates in routing rules)
    /// 可选：用户标签（参与路由规则）
    pub user: Option<String>,
    /// Optional: Sniffed SNI/Host (for rule matching)
    /// 可选：SNI/Host（嗅探/规则）
    pub sniff_host: Option<String>,
    /// Transport layer type (tcp/udp/other)
    /// 传输层类型（tcp/udp/other）
    pub transport: Option<Transport>,
    /// Soft timeout: used for connect timeout
    /// 软超时：用于 connect 的超时
    pub connect_timeout: Option<Duration>,
    /// Deadline: stricter unified deadline
    /// 截止时间：比超时更强的统一截止
    pub deadline: Option<Instant>,
}

impl Default for ConnectParams {
    fn default() -> Self {
        Self {
            // target 由调用侧必填
            target: Address::Domain(String::new(), 0),
            inbound: None,
            user: None,
            sniff_host: None,
            transport: None,
            connect_timeout: None,
            deadline: None,
        }
    }
}
