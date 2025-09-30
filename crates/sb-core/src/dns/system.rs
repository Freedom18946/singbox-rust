use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;

use super::{DnsAnswer, DnsResolver};

/// SystemResolver：
// - 优先匹配静态表（SB_DNS_STATIC / SB_DNS_STATIC_TTL_S）
// - 否则使用 tokio::net::lookup_host 收集 A/AAAA
// - 无法从系统解析 TTL，采用默认 TTL（SB_DNS_DEFAULT_TTL_S）
pub struct SystemResolver {
    default_ttl: Duration,
}

impl SystemResolver {
    pub fn new(default_ttl: Duration) -> Self {
        Self { default_ttl }
    }
}

#[async_trait]
impl DnsResolver for SystemResolver {
    async fn resolve(&self, host: &str) -> Result<DnsAnswer> {
        // 系统解析（tokio）。端口 0 仅用于解析，不参与连接。
        let mut out = Vec::new();
        let iter = tokio::net::lookup_host((host, 0)).await?;
        for sa in iter {
            out.push(sa.ip());
        }
        Ok(DnsAnswer::new(
            out,
            self.default_ttl,
            super::cache::Source::System,
            super::cache::Rcode::NoError,
        ))
    }
}
