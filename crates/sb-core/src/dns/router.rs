//! DNS 路由/缓存层：对外暴露**非泛型**的 `DnsCache`，内部用泛型缓存承载不同传输实现。
//! 这样上层无需携带泛型参数，保持旧用法 `DnsCache` 不变。
use super::{DnsTransport, Record, SystemResolverTransport, TtlCache};
use anyhow::Result;
use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

/// 内部泛型缓存（不对外暴露，避免上层被迫携带泛型）
struct Cache<T: DnsTransport> {
    transport: T,
    cache: TtlCache<String, Vec<IpAddr>>,
    default_ttl: Duration,
}

impl<T: DnsTransport> Cache<T> {
    fn new(transport: T, capacity: usize, default_ttl: Duration) -> Self {
        Self {
            transport,
            cache: TtlCache::new(capacity),
            default_ttl,
        }
    }

    /// 解析域名（A/AAAA），优先命中缓存；未命中则传输层查询并写回缓存
    async fn lookup(&mut self, host: &str) -> Result<Vec<IpAddr>> {
        if let Some(v) = self.cache.get_cloned(&host.to_string()) {
            return Ok(v);
        }
        let recs = self.transport.query_a(host).await?;
        let mut ips = Vec::new();
        let mut ttl = self.default_ttl;
        for r in recs {
            // 目前 Record 只有 A 变体；直接解构避免 irrefutable if-let 告警
            let Record::A(ip, t) = r;
            ips.push(ip);
            let suggested = Duration::from_secs(t as u64);
            if suggested < ttl {
                ttl = suggested;
            }
        }
        if !ips.is_empty() {
            self.cache.put(host.to_string(), ips.clone(), ttl);
        }
        Ok(ips)
    }
}

/// 对外的非泛型缓存：默认绑定**系统解析传输层**，保持上层 `DnsCache` 的旧用法不变
pub struct DnsCache {
    inner: Cache<SystemResolverTransport>,
    cap: usize,
    default_ttl: Duration,
}

impl DnsCache {
    /// 兼容旧用法：只传入默认 TTL；容量固定为 1024；传输层使用 SystemResolverTransport
    pub fn new(default_ttl: Duration) -> Self {
        let cap = 1024;
        Self {
            inner: Cache::new(
                SystemResolverTransport::new(default_ttl.as_secs() as u32),
                cap,
                default_ttl,
            ),
            cap,
            default_ttl,
        }
    }

    /// 可选：指定容量版本
    pub fn with_capacity(capacity: usize, default_ttl: Duration) -> Self {
        Self {
            inner: Cache::new(
                SystemResolverTransport::new(default_ttl.as_secs() as u32),
                capacity,
                default_ttl,
            ),
            cap: capacity,
            default_ttl,
        }
    }

    /// 解析域名（A/AAAA），优先命中缓存；未命中则查询并写回
    pub async fn lookup(&mut self, host: &str) -> Result<Vec<IpAddr>> {
        self.inner.lookup(host).await
    }

    /// 上层同步路径使用：仅从缓存返回结果，不触发网络 I/O；**只读**，不要求 `&mut self`
    /// 与 `engine.rs` 的旧名保持一致（resolve_cached_or_lookup），但语义明确为“只查缓存”
    pub fn resolve_cached_or_lookup(&self, host: &str) -> Option<Vec<IpAddr>> {
        self.inner.cache.peek_cloned(&host.to_string())
    }
}

impl Default for DnsCache {
    fn default() -> Self {
        // 保守默认 TTL = 60s
        Self::new(Duration::from_secs(60))
    }
}

impl Clone for DnsCache {
    fn clone(&self) -> Self {
        // 克隆时不复制内部 LRU 数据，避免深拷贝；参数保持一致
        DnsCache::with_capacity(self.cap, self.default_ttl)
    }
}

impl fmt::Debug for DnsCache {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DnsCache")
            .field("cap", &self.cap)
            .field("default_ttl_secs", &self.default_ttl.as_secs())
            .finish()
    }
}
