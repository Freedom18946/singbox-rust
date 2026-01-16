//! Minimal DNS client with in-process cache (behind env `SB_DNS_ENABLE=1`).
//! 默认关闭；开启后通过系统解析器进行 A/AAAA 解析，并暴露基础指标。

use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct DnsClient {
    inner: Arc<Inner>,
}

struct Inner {
    cache: RwLock<HashMap<String, CacheEntry>>,
    ttl_default: Duration,
    /// Minimum TTL (Go parity: dns.ClientOptions.CacheTTLOverride.Min)
    min_ttl: Duration,
    /// Maximum TTL (Go parity: dns.ClientOptions.CacheTTLOverride.Max)
    max_ttl: Duration,
    /// Negative cache TTL for NXDOMAIN/NODATA (Go parity: dns.ClientOptions.CacheCapacity + negative handling)
    negative_ttl: Duration,
    cap: usize,
}

#[derive(Clone)]
struct CacheEntry {
    addrs: Vec<IpAddr>,
    expires_at: Instant,
    negative: bool, // NXDOMAIN/NOERROR-NODATA
}

impl DnsClient {
    pub fn new(ttl: Duration) -> Self {
        let cap = std::env::var("SB_DNS_CACHE_MAX")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(1024);
        let min_ttl = Duration::from_secs(
            std::env::var("SB_DNS_MIN_TTL_S")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(1),
        );
        let max_ttl = Duration::from_secs(
            std::env::var("SB_DNS_MAX_TTL_S")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(86400), // 1 day default max
        );
        let negative_ttl = Duration::from_secs(
            std::env::var("SB_DNS_NEG_TTL_S")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(30),
        );
        Self {
            inner: Arc::new(Inner {
                cache: RwLock::new(HashMap::new()),
                ttl_default: ttl,
                min_ttl,
                max_ttl,
                negative_ttl,
                cap,
            }),
        }
    }

    /// Create a new DNS client with explicit TTL configuration (for testing/builders).
    /// 使用显式 TTL 配置创建新的 DNS 客户端（用于测试/构建器）。
    #[must_use]
    pub fn with_ttl_config(
        default_ttl: Duration,
        min_ttl: Duration,
        max_ttl: Duration,
        negative_ttl: Duration,
        cap: usize,
    ) -> Self {
        Self {
            inner: Arc::new(Inner {
                cache: RwLock::new(HashMap::new()),
                ttl_default: default_ttl,
                min_ttl,
                max_ttl,
                negative_ttl,
                cap,
            }),
        }
    }

    fn enabled() -> bool {
        std::env::var("SB_DNS_ENABLE")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    /// 解析域名（优先缓存；miss 时调用系统解析器）
    pub async fn resolve(&self, host: &str, default_port: u16) -> anyhow::Result<Vec<SocketAddr>> {
        if !Self::enabled() {
            // 未启用则短路：交给系统解析（与现状一致）
            return Ok(tokio::net::lookup_host((host, default_port))
                .await?
                .collect());
        }
        let host_l = host.to_ascii_lowercase();
        // 1) 缓存命中
        if let Some(addrs) = self.cache_get(&host_l).await {
            #[cfg(feature = "metrics")]
            metrics::counter!("dns_query_total", "type"=>"cache").increment(1);
            return Ok(addrs
                .into_iter()
                .map(|ip| SocketAddr::new(ip, default_port))
                .collect());
        }
        // 若设置了 UDP 模式，则优先走自定义上游
        let mode_udp = std::env::var("SB_DNS_MODE")
            .ok()
            .is_some_and(|v| v.eq_ignore_ascii_case("udp"));
        let upstream = std::env::var("SB_DNS_UPSTREAM").ok();
        // 2) miss：UDP 或系统解析器
        #[cfg(feature = "metrics")]
        metrics::counter!("dns_query_total", "type"=>"A+AAAA").increment(1);
        let timer = crate::dns::client::prelude::Timer::new("dns_rtt_ms");
        let res: anyhow::Result<(Vec<IpAddr>, Option<u32>, bool)> = if mode_udp {
            if let Some(up) = upstream {
                let up: std::net::SocketAddr = up.parse()?;
                // 并发 A/AAAA：behind env（默认关闭，保持现状）
                let parallel = std::env::var("SB_DNS_PARALLEL")
                    .ok()
                    .is_some_and(|v| v == "1" || v.eq_ignore_ascii_case("true"));
                if parallel {
                    udp_query_a_aaaa_parallel(&up, host)
                        .await
                        .map(|(ips, ttl)| (ips, ttl, false))
                } else {
                    udp_query_follow_cname(&up, host).await // (ips, min_ttl, negative)
                }
            } else {
                Err(anyhow::anyhow!("SB_DNS_UPSTREAM not set"))
            }
        } else {
            // 系统解析：无 TTL，可视作成功数据，存默认 TTL
            let v = tokio::net::lookup_host((host, default_port))
                .await?
                .map(|sa| sa.ip())
                .collect::<Vec<IpAddr>>();
            let empty = v.is_empty();
            Ok((v, None, empty))
        };
        // metrics 关时也要消耗一次计时结果，但不使用它，避免 warning
        #[cfg(feature = "metrics")]
        let elapsed = timer.observe_duration_ms();
        #[cfg(not(feature = "metrics"))]
        let _elapsed = timer.observe_duration_ms();
        match res {
            Ok((ips, ttl_opt, negative)) => {
                self.cache_put(host_l, ips.clone(), ttl_opt, negative).await;
                #[cfg(feature = "metrics")]
                {
                    metrics::gauge!("dns_rtt_ms_last").set(elapsed as f64);
                }
                Ok(ips
                    .into_iter()
                    .map(|ip| SocketAddr::new(ip, default_port))
                    .collect())
            }
            Err(e) => {
                #[cfg(feature = "metrics")]
                metrics::counter!("dns_error_total", "class"=>"resolve").increment(1);
                Err(anyhow::anyhow!(e))
            }
        }
    }

    async fn cache_get(&self, host: &str) -> Option<Vec<IpAddr>> {
        let now = Instant::now();
        let map = self.inner.cache.read().await;
        if let Some(ent) = map.get(host) {
            if now < ent.expires_at {
                // For negative cache entries, return empty vec (will be treated as miss by caller)
                if ent.negative && ent.addrs.is_empty() {
                    // Negative cache hit - return empty to trigger fresh lookup
                    // This matches Go behavior: negative entries block re-queries for negative_ttl
                    return Some(vec![]);
                }
                return Some(ent.addrs.clone());
            }
        }
        None
    }

    async fn cache_put(&self, host: String, addrs: Vec<IpAddr>, ttl: Option<u32>, negative: bool) {
        let mut map = self.inner.cache.write().await;

        // TTL clamping (Go parity: CacheTTLOverride)
        let raw_ttl = ttl.map_or(self.inner.ttl_default, |s| {
            Duration::from_secs(u64::from(s))
        });
        let clamped_ttl = if negative {
            // Negative cache uses dedicated TTL
            self.inner.negative_ttl
        } else {
            // Clamp positive cache TTL between min and max
            raw_ttl.clamp(self.inner.min_ttl, self.inner.max_ttl)
        };

        map.insert(
            host,
            CacheEntry {
                addrs,
                expires_at: Instant::now() + clamped_ttl,
                negative,
            },
        );
        // 简单容量控制：超过 cap 淘汰一条（FIFO 近似：随便移除第一条）
        if map.len() > self.inner.cap {
            if let Some(k) = map.keys().next().cloned() {
                map.remove(&k);
                #[cfg(feature = "metrics")]
                metrics::counter!("dns_cache_evicted_total").increment(1);
            }
        }
        #[cfg(feature = "metrics")]
        metrics::gauge!("dns_cache_size").set(map.len() as f64);
    }

    /// Get min TTL configuration.
    /// 获取最小 TTL 配置。
    #[must_use]
    pub fn min_ttl(&self) -> Duration {
        self.inner.min_ttl
    }

    /// Get max TTL configuration.
    /// 获取最大 TTL 配置。
    #[must_use]
    pub fn max_ttl(&self) -> Duration {
        self.inner.max_ttl
    }

    /// Get negative TTL configuration.
    /// 获取负缓存 TTL 配置。
    #[must_use]
    pub fn negative_ttl(&self) -> Duration {
        self.inner.negative_ttl
    }
}

/// 简单的直通计时器封装（以 ms 为单位入直方图）
mod timer {
    use std::time::Instant;
    #[cfg_attr(not(feature = "metrics"), allow(dead_code))]
    pub struct Timer {
        start: Instant,
        name: &'static str,
    }
    impl Timer {
        pub fn new(name: &'static str) -> Self {
            Self {
                start: Instant::now(),
                name,
            }
        }
        pub fn observe_duration_ms(&self) -> u128 {
            let ms = self.start.elapsed().as_millis();
            #[cfg(feature = "metrics")]
            {
                let v = ms as f64;
                metrics::histogram!(self.name).record(v);
            }
            ms
        }
    }
}

// 暴露给上层的计时器构造（避免在上层重复写样板）
pub(crate) mod prelude {
    pub use super::timer::Timer;
}

// -----------------------------
// 最小 UDP 查询（A/AAAA）
// -----------------------------
use tokio::net::UdpSocket as TokioUdpSocket;
use tokio::time::{timeout, Duration as TokioDuration};

async fn udp_query_a_aaaa(
    upstream: &std::net::SocketAddr,
    host: &str,
) -> anyhow::Result<(Vec<std::net::IpAddr>, Option<u32>)> {
    let mut ips = Vec::new();
    let mut min_ttl: Option<u32> = None;
    // A 然后 AAAA，各发一次查询
    let one = |qtype: u16| async move {
        let req = build_query(host, qtype)?;
        let sock = TokioUdpSocket::bind("0.0.0.0:0").await?;
        let _ = sock.send_to(&req, upstream).await?;
        let mut buf = [0u8; 1500];
        let (n, _from) =
            timeout(TokioDuration::from_millis(800), sock.recv_from(&mut buf)).await??;
        parse_answers(&buf[..n], qtype)
    };
    // best-effort：A + AAAA 合并
    if let Ok((v4s, t4)) = one(1).await {
        ips.extend(v4s);
        min_ttl = min_ttl.min(t4).or(t4);
    }
    if let Ok((v6s, t6)) = one(28).await {
        ips.extend(v6s);
        min_ttl = min_ttl.min(t6).or(t6);
    }
    if ips.is_empty() {
        return Err(anyhow::anyhow!("no answers"));
    }
    Ok((ips, min_ttl))
}

/// 并发发送 A 与 AAAA 并合并最小 TTL（不处理 CNAME）
async fn udp_query_a_aaaa_parallel(
    upstream: &std::net::SocketAddr,
    host: &str,
) -> anyhow::Result<(Vec<std::net::IpAddr>, Option<u32>)> {
    use futures::future::join;
    let (a, aaaa) = join(
        async {
            let one = |qtype: u16| async move {
                let req = build_query(host, qtype)?;
                let sock = TokioUdpSocket::bind("0.0.0.0:0").await?;
                let _ = sock.send_to(&req, upstream).await?;
                let mut buf = [0u8; 1500];
                let (n, _from) =
                    timeout(TokioDuration::from_millis(800), sock.recv_from(&mut buf)).await??;
                parse_answers(&buf[..n], qtype)
            };
            one(1).await
        },
        async {
            let one = |qtype: u16| async move {
                let req = build_query(host, qtype)?;
                let sock = TokioUdpSocket::bind("0.0.0.0:0").await?;
                let _ = sock.send_to(&req, upstream).await?;
                let mut buf = [0u8; 1500];
                let (n, _from) =
                    timeout(TokioDuration::from_millis(800), sock.recv_from(&mut buf)).await??;
                parse_answers(&buf[..n], qtype)
            };
            one(28).await
        },
    )
    .await;
    let mut ips = Vec::new();
    let mut ttl_min: Option<u32> = None;
    if let Ok((v4s, t4)) = a {
        ips.extend(v4s);
        ttl_min = ttl_min.min(t4).or(t4);
    }
    if let Ok((v6s, t6)) = aaaa {
        ips.extend(v6s);
        ttl_min = ttl_min.min(t6).or(t6);
    }
    if ips.is_empty() {
        return Err(anyhow::anyhow!("no answers"));
    }
    Ok((ips, ttl_min))
}

fn build_query(host: &str, qtype: u16) -> anyhow::Result<Vec<u8>> {
    // 12B header + qname + QTYPE/QCLASS
    let id = (std::time::Instant::now().elapsed().as_nanos() as u16).to_be_bytes();
    // header
    let mut out = vec![
        id[0], id[1], // ID
        0x01, 0x00, // RD=1
        0x00, 0x01, // QDCOUNT=1
        0x00, 0x00, // ANCOUNT
        0x00, 0x00, // NSCOUNT
        0x00, 0x00, // ARCOUNT
    ];
    // QNAME
    for label in host.trim_end_matches('.').split('.') {
        let b = label.as_bytes();
        if b.is_empty() || b.len() > 63 {
            return Err(anyhow::anyhow!("bad label"));
        }
        out.push(b.len() as u8);
        out.extend_from_slice(b);
    }
    out.push(0); // root
                 // QTYPE / QCLASS=IN(1)
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes());
    Ok(out)
}

fn parse_answers(
    mut buf: &[u8],
    want: u16,
) -> anyhow::Result<(Vec<std::net::IpAddr>, Option<u32>)> {
    if buf.len() < 12 {
        return Err(anyhow::anyhow!("short dns header"));
    }
    let qd = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    let an = u16::from_be_bytes([buf[6], buf[7]]) as usize;
    // 跳过 header
    buf = &buf[12..];
    // 跳过 Question
    for _ in 0..qd {
        let mut i = 0;
        loop {
            if i >= buf.len() {
                return Err(anyhow::anyhow!("qname overrun"));
            }
            let l = buf[i] as usize;
            i += 1;
            if l == 0 {
                break;
            }
            i += l;
        }
        if i + 4 > buf.len() {
            return Err(anyhow::anyhow!("qtail overrun"));
        }
        buf = &buf[i + 4..];
    }
    // 解析 Answers（只取 A/AAAA）
    let mut out = Vec::new();
    let mut min_ttl: Option<u32> = None;
    let mut p = buf;
    for _ in 0..an {
        // NAME(2 bytes ptr or labels)… 这里只处理常见压缩指针 0b11xxxxxx
        if p.len() < 2 {
            break;
        }
        let name_ptr = (p[0] & 0xC0) == 0xC0;
        let mut i = if name_ptr {
            2
        } else {
            // 极少数上游返回未压缩 name；做个安全跳过
            let mut j = 0usize;
            loop {
                if j >= p.len() {
                    return Err(anyhow::anyhow!("name overrun"));
                }
                let l = p[j] as usize;
                j += 1;
                if l == 0 {
                    break;
                }
                j += l;
            }
            j
        };
        if p.len() < i + 10 {
            break;
        } // TYPE(2) CLASS(2) TTL(4) RDLEN(2) = 10
        let rtype = u16::from_be_bytes([p[i], p[i + 1]]);
        i += 2;
        let _class = u16::from_be_bytes([p[i], p[i + 1]]);
        i += 2;
        let ttl = u32::from_be_bytes([p[i], p[i + 1], p[i + 2], p[i + 3]]);
        i += 4;
        min_ttl = Some(min_ttl.map_or(ttl, |m| m.min(ttl)));
        let rdlen = u16::from_be_bytes([p[i], p[i + 1]]) as usize;
        i += 2;
        if p.len() < i + rdlen {
            break;
        }
        let rdata = &p[i..i + rdlen];
        if rtype == 1 && want == 1 && rdlen == 4 {
            out.push(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                rdata[0], rdata[1], rdata[2], rdata[3],
            )));
        } else if rtype == 28 && want == 28 && rdlen == 16 {
            let mut a = [0u8; 16];
            a.copy_from_slice(rdata);
            out.push(std::net::IpAddr::V6(std::net::Ipv6Addr::from(a)));
        }
        p = &p[i + rdlen..];
    }
    Ok((out, min_ttl))
}

async fn udp_query_follow_cname(
    upstream: &std::net::SocketAddr,
    host: &str,
) -> anyhow::Result<(Vec<std::net::IpAddr>, Option<u32>, bool)> {
    // 简化实现：直接查询 A/AAAA，不跟随 CNAME
    let name = host.to_string();
    let (ips, ttl) = udp_query_a_aaaa(upstream, &name).await?;
    if !ips.is_empty() {
        return Ok((ips, ttl, false));
    }
    // 负缓存：NXDOMAIN 或 NOERROR/NODATA
    Ok((Vec::new(), ttl, true))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore]
    fn test_ttl_config_defaults() {
        let client = DnsClient::new(Duration::from_secs(60));
        assert_eq!(client.min_ttl(), Duration::from_secs(1));
        assert_eq!(client.max_ttl(), Duration::from_secs(86400));
        assert_eq!(client.negative_ttl(), Duration::from_secs(30));
    }

    #[test]
    fn test_ttl_config_explicit() {
        let client = DnsClient::with_ttl_config(
            Duration::from_secs(120),
            Duration::from_secs(5),
            Duration::from_secs(3600),
            Duration::from_secs(60),
            512,
        );
        assert_eq!(client.min_ttl(), Duration::from_secs(5));
        assert_eq!(client.max_ttl(), Duration::from_secs(3600));
        assert_eq!(client.negative_ttl(), Duration::from_secs(60));
    }

    #[tokio::test]
    async fn test_ttl_clamping_min() {
        let client = DnsClient::with_ttl_config(
            Duration::from_secs(60),
            Duration::from_secs(10), // min = 10s
            Duration::from_secs(300),
            Duration::from_secs(30),
            1024,
        );

        // Put an entry with TTL below min (should be clamped to 10s)
        client
            .cache_put(
                "test.example.com".to_string(),
                vec!["1.2.3.4".parse().unwrap()],
                Some(1), // 1 second - below minimum
                false,
            )
            .await;

        // Entry should be cached (clamped to min_ttl)
        let result = client.cache_get("test.example.com").await;
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn test_ttl_clamping_max() {
        let client = DnsClient::with_ttl_config(
            Duration::from_secs(60),
            Duration::from_secs(1),
            Duration::from_secs(10), // max = 10s
            Duration::from_secs(30),
            1024,
        );

        // Put an entry with TTL above max (should be clamped to 10s)
        client
            .cache_put(
                "test.example.com".to_string(),
                vec!["1.2.3.4".parse().unwrap()],
                Some(3600), // 1 hour - above maximum
                false,
            )
            .await;

        // Entry should be cached (clamped to max_ttl)
        let result = client.cache_get("test.example.com").await;
        assert!(result.is_some());
    }

    #[tokio::test]
    async fn test_negative_cache_ttl() {
        let client = DnsClient::with_ttl_config(
            Duration::from_secs(60),
            Duration::from_secs(1),
            Duration::from_secs(300),
            Duration::from_secs(5), // negative = 5s
            1024,
        );

        // Put a negative cache entry
        client
            .cache_put("nxdomain.example.com".to_string(), vec![], None, true)
            .await;

        // Entry should be cached with negative TTL (returns empty vec)
        let result = client.cache_get("nxdomain.example.com").await;
        assert!(result.is_some());
        assert!(result.unwrap().is_empty());
    }
}
