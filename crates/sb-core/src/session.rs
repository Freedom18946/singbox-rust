use crate::net::Address;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub enum Transport {
    Tcp,
    Udp,
    Other,
}

#[derive(Debug, Clone)]
pub struct ConnectParams {
    pub target: Address,
    /// 可选：来源入站标识（如 "tun" / 具体实例名）
    pub inbound: Option<String>,
    /// 可选：用户标签（参与路由规则）
    pub user: Option<String>,
    /// 可选：SNI/Host（嗅探/规则）
    pub sniff_host: Option<String>,
    /// 传输层类型（tcp/udp/other）
    pub transport: Option<Transport>,
    /// 软超时：用于 connect 的超时
    pub connect_timeout: Option<Duration>,
    /// 截止时间：比超时更强的统一截止
    pub deadline: Option<Instant>,
}

impl Default for ConnectParams {
    fn default() -> Self {
        Self {
            // target 由调用侧必填
            target: Address::Domain("".into(), 0),
            inbound: None,
            user: None,
            sniff_host: None,
            transport: None,
            connect_timeout: None,
            deadline: None,
        }
    }
}
