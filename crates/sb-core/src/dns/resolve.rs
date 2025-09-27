#[cfg(feature = "dns_cache")]
use super::cache::{DnsCache, QType};
use anyhow::Result;
use std::net::SocketAddr;
use tokio::net::lookup_host;

#[derive(Clone, Copy, Debug)]
pub enum DnsBackend {
    System,
    Udp,
    Dot,
    Doh,
    Auto,
}

#[derive(Clone, Copy, Debug)]
#[allow(clippy::upper_case_acronyms)]
enum QSel {
    A,
    AAAA,
    Auto,
}

fn qsel_from_env() -> QSel {
    match std::env::var("SB_DNS_QTYPE")
        .unwrap_or_else(|_| "auto".into())
        .to_ascii_lowercase()
        .as_str()
    {
        "a" => QSel::A,
        "aaaa" => QSel::AAAA,
        _ => QSel::Auto,
    }
}

fn backend_from_env() -> DnsBackend {
    match std::env::var("SB_DNS_MODE")
        .unwrap_or_else(|_| "system".into())
        .to_ascii_lowercase()
        .as_str()
    {
        "system" => DnsBackend::System,
        "udp" => DnsBackend::Udp,
        "dot" => DnsBackend::Dot,
        "doh" => DnsBackend::Doh,
        "auto" => DnsBackend::Auto,
        _ => DnsBackend::System,
    }
}

fn timeout_from_env() -> u64 {
    std::env::var("SB_DNS_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(1500)
}

#[cfg(any(test, feature = "dev-cli"))]
fn doh_url_from_env() -> String {
    std::env::var("SB_DNS_DOH_URL")
        .unwrap_or_else(|_| "https://cloudflare-dns.com/dns-query".into())
}

#[cfg(any(test, feature = "dev-cli"))]
fn dot_addr_from_env() -> Option<SocketAddr> {
    std::env::var("SB_DNS_DOT_ADDR")
        .ok()
        .and_then(|s| s.parse::<SocketAddr>().ok())
}

/// 统一解析入口：返回 (IP 列表, 可选 TTL 秒)
pub async fn resolve_all(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let backend = backend_from_env();
    let timeout = timeout_from_env();
    let qsel = qsel_from_env();
    #[cfg(feature = "metrics")]
    let t0 = std::time::Instant::now();
    let host_owned = host.to_string();
    let _run = move |b: DnsBackend| {
        let host = host_owned.clone();
        let port = port;
        let timeout = timeout;
        async move {
            match b {
                DnsBackend::System => system_resolve(&host, port).await,
                DnsBackend::Udp => udp_resolve(&host, port, timeout).await,
                DnsBackend::Dot => dot_resolve(&host, port, timeout).await,
                DnsBackend::Doh => doh_resolve(&host, port, timeout).await,
                DnsBackend::Auto => unreachable!(),
            }
        }
    };
    // ========== 缓存封装开始 ==========
    #[cfg(feature = "dns_cache")]
    {
        if cache_enabled() {
            return resolve_with_cache(backend, host.to_string(), port, timeout, qsel, _run).await;
        }
    }
    // ========== 无缓存路径 ==========
    let out = match backend {
        DnsBackend::Auto => resolve_qsel(qsel, host, port, timeout, backend).await?,
        b => resolve_qsel_qtype(b, qsel, host, port, timeout).await?,
    };
    #[cfg(feature = "metrics")]
    {
        let dt = t0.elapsed().as_secs_f64();
        let qtype_label = match qsel {
            QSel::A => "a",
            QSel::AAAA => "aaaa",
            QSel::Auto => "auto",
        };
        #[cfg(any(test, feature = "dev-cli"))]
        let backend_label = label(backend);
        #[cfg(not(any(test, feature = "dev-cli")))]
        let backend_label = "default";
        metrics::histogram!("dns_rtt_seconds", "backend"=>backend_label, "qtype"=>qtype_label)
            .record(dt);
    }
    Ok(out)
}

#[cfg(any(test, feature = "dev-cli"))]
fn label(b: DnsBackend) -> &'static str {
    match b {
        DnsBackend::System => "system",
        DnsBackend::Udp => "udp",
        DnsBackend::Dot => "dot",
        DnsBackend::Doh => "doh",
        DnsBackend::Auto => "auto",
    }
}

async fn system_resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let addrs = lookup_host((host, port)).await?;
    Ok(addrs.collect())
}

async fn resolve_qsel(
    qsel: QSel,
    host: &str,
    port: u16,
    timeout: u64,
    backend: DnsBackend,
) -> Result<Vec<SocketAddr>> {
    match qsel {
        QSel::A => resolve_qsel_qtype(backend, QSel::A, host, port, timeout).await,
        QSel::AAAA => resolve_qsel_qtype(backend, QSel::AAAA, host, port, timeout).await,
        QSel::Auto => {
            // Auto: concurrent A/AAAA, merge results
            let a_fut = resolve_qsel_qtype(backend, QSel::A, host, port, timeout);
            let aaaa_fut = resolve_qsel_qtype(backend, QSel::AAAA, host, port, timeout);
            let (ra, rb) = tokio::join!(a_fut, aaaa_fut);
            let mut out = Vec::<SocketAddr>::new();
            if let Ok(v) = ra {
                out.extend(v);
            }
            if let Ok(v) = rb {
                out.extend(v);
            }
            Ok(out)
        }
    }
}

async fn resolve_qsel_qtype(
    backend: DnsBackend,
    qsel: QSel,
    host: &str,
    port: u16,
    timeout_ms: u64,
) -> Result<Vec<SocketAddr>> {
    let qtype = match qsel {
        QSel::A => 1,
        QSel::AAAA => 28,
        QSel::Auto => 1,
    };
    #[cfg(feature = "metrics")]
    {
        let qtype_label = match qsel {
            QSel::A => "a",
            QSel::AAAA => "aaaa",
            QSel::Auto => "auto",
        };
        #[cfg(any(test, feature = "dev-cli"))]
        let backend_label = label(backend);
        #[cfg(not(any(test, feature = "dev-cli")))]
        let backend_label = "default";
        metrics::counter!("dns_query_total", "backend"=>backend_label, "qtype"=>qtype_label)
            .increment(1);
    }
    match backend {
        DnsBackend::System => system_resolve(host, port).await,
        DnsBackend::Udp => udp_resolve_qtype(host, port, timeout_ms, qtype).await,
        DnsBackend::Dot => dot_resolve_qtype(host, port, timeout_ms, qtype).await,
        DnsBackend::Doh => doh_resolve_qtype(host, port, timeout_ms, qtype).await,
        DnsBackend::Auto => {
            if let Ok(v) = udp_resolve_qtype(host, port, timeout_ms, qtype).await {
                return Ok(v);
            }
            if let Ok(v) = dot_resolve_qtype(host, port, timeout_ms, qtype).await {
                return Ok(v);
            }
            doh_resolve_qtype(host, port, timeout_ms, qtype).await
        }
    }
}

async fn udp_resolve_qtype(
    _host: &str,
    _port: u16,
    _timeout_ms: u64,
    _qtype: u16,
) -> Result<Vec<SocketAddr>> {
    #[cfg(feature = "dns_udp")]
    {
        use crate::dns::udp::{build_query, parse_answers};
        use std::time::Duration;
        let q = build_query(_host, _qtype)?;
        let svr = std::env::var("SB_DNS_UDP_SERVER")
            .unwrap_or_else(|_| "1.1.1.1:53".into())
            .parse::<SocketAddr>()?;
        let sock = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
        sock.send_to(&q, svr).await?;
        let mut buf = [0u8; 1500];
        let (n, _) =
            tokio::time::timeout(Duration::from_millis(_timeout_ms), sock.recv_from(&mut buf))
                .await??;
        let (ips, _ttl) = parse_answers(&buf[..n], _qtype)?;
        Ok(ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, _port))
            .collect())
    }
    #[cfg(not(feature = "dns_udp"))]
    {
        Err(anyhow::anyhow!("dns_udp feature disabled"))
    }
}

async fn udp_resolve(host: &str, port: u16, timeout_ms: u64) -> Result<Vec<SocketAddr>> {
    udp_resolve_qtype(host, port, timeout_ms, 1).await
}

#[cfg(feature = "dns_dot")]
async fn dot_resolve_qtype(
    host: &str,
    port: u16,
    timeout_ms: u64,
    qtype: u16,
) -> Result<Vec<SocketAddr>> {
    use crate::dns::dot::query_dot_once;
    #[cfg(any(test, feature = "dev-cli"))]
    let addr = dot_addr_from_env().unwrap_or_else(|| "1.1.1.1:853".parse().unwrap());
    #[cfg(not(any(test, feature = "dev-cli")))]
    let addr = "1.1.1.1:853".parse().unwrap();
    let (ips, _ttl) = query_dot_once(addr, host, qtype, timeout_ms).await?;
    Ok(ips
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect())
}

#[cfg(feature = "dns_dot")]
async fn dot_resolve(host: &str, port: u16, timeout_ms: u64) -> Result<Vec<SocketAddr>> {
    dot_resolve_qtype(host, port, timeout_ms, 1).await
}

#[cfg(not(feature = "dns_dot"))]
async fn dot_resolve_qtype(
    _host: &str,
    _port: u16,
    _timeout_ms: u64,
    _qtype: u16,
) -> Result<Vec<SocketAddr>> {
    Err(anyhow::anyhow!("dns_dot feature disabled"))
}

#[cfg(not(feature = "dns_dot"))]
async fn dot_resolve(_host: &str, _port: u16, _timeout_ms: u64) -> Result<Vec<SocketAddr>> {
    Err(anyhow::anyhow!("dns_dot feature disabled"))
}

#[cfg(feature = "dns_doh")]
async fn doh_resolve_qtype(
    host: &str,
    port: u16,
    timeout_ms: u64,
    qtype: u16,
) -> Result<Vec<SocketAddr>> {
    use crate::dns::doh::query_doh_once;
    #[cfg(any(test, feature = "dev-cli"))]
    let url = doh_url_from_env();
    #[cfg(not(any(test, feature = "dev-cli")))]
    let url = "https://cloudflare-dns.com/dns-query".to_string();
    let (ips, _ttl) = query_doh_once(&url, host, qtype, timeout_ms).await?;
    Ok(ips
        .into_iter()
        .map(|ip| SocketAddr::new(ip, port))
        .collect())
}

#[cfg(feature = "dns_doh")]
async fn doh_resolve(host: &str, port: u16, timeout_ms: u64) -> Result<Vec<SocketAddr>> {
    doh_resolve_qtype(host, port, timeout_ms, 1).await
}

#[cfg(not(feature = "dns_doh"))]
async fn doh_resolve_qtype(
    _host: &str,
    _port: u16,
    _timeout_ms: u64,
    _qtype: u16,
) -> Result<Vec<SocketAddr>> {
    Err(anyhow::anyhow!("dns_doh feature disabled"))
}

#[cfg(not(feature = "dns_doh"))]
async fn doh_resolve(_host: &str, _port: u16, _timeout_ms: u64) -> Result<Vec<SocketAddr>> {
    Err(anyhow::anyhow!("dns_doh feature disabled"))
}

/// Compatibility function for the simple resolver API
pub async fn resolve_socketaddr(host: &str, port: u16) -> std::io::Result<SocketAddr> {
    let addrs = resolve_all(host, port)
        .await
        .map_err(std::io::Error::other)?;
    addrs
        .first()
        .copied()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "no addresses found"))
}

/// Backward compatibility: resolve_all but return io::Result
pub async fn resolve_all_compat(host: &str, port: u16) -> std::io::Result<Vec<SocketAddr>> {
    resolve_all(host, port).await.map_err(std::io::Error::other)
}

#[cfg(feature = "dns_cache")]
fn cache_enabled() -> bool {
    std::env::var("SB_DNS_CACHE_ENABLE")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

#[cfg(feature = "dns_cache")]
fn cache_params() -> (usize, u64, u64) {
    let cap = std::env::var("SB_DNS_CACHE_CAP")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(4096);
    let neg = std::env::var("SB_DNS_CACHE_NEG_TTL_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(20_000);
    let stale = std::env::var("SB_DNS_CACHE_STALE_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0);
    (cap, neg, stale)
}

#[cfg(feature = "dns_cache")]
async fn resolve_with_cache<F, Fut>(
    backend: DnsBackend,
    host: String,
    port: u16,
    timeout: u64,
    qsel: QSel,
    run: F,
) -> Result<Vec<SocketAddr>>
where
    F: Fn(DnsBackend) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<Vec<SocketAddr>>> + Send,
{
    use std::sync::OnceLock;
    static CACHE: OnceLock<DnsCache> = OnceLock::new();
    let (cap, _neg, _stale) = cache_params();
    let cache = CACHE.get_or_init(|| DnsCache::new(cap));
    // For auto mode, we handle both A and AAAA separately in cache
    match qsel {
        QSel::Auto => {
            // Auto: concurrent A/AAAA queries with cache
            let a_fut = resolve_cached_qtype(cache, backend, &host, port, timeout, QType::A);
            let aaaa_fut = resolve_cached_qtype(cache, backend, &host, port, timeout, QType::AAAA);
            let (ra, rb) = tokio::join!(a_fut, aaaa_fut);
            let mut out = Vec::<SocketAddr>::new();
            if let Ok(v) = ra {
                out.extend(v);
            }
            if let Ok(v) = rb {
                out.extend(v);
            }
            return Ok(out);
        }
        QSel::A => {
            return resolve_cached_qtype(cache, backend, &host, port, timeout, QType::A).await;
        }
        QSel::AAAA => {
            return resolve_cached_qtype(cache, backend, &host, port, timeout, QType::AAAA).await;
        }
    }
}

#[cfg(feature = "dns_cache")]
async fn resolve_cached_qtype(
    cache: &'static DnsCache,
    backend: DnsBackend,
    host: &str,
    port: u16,
    timeout: u64,
    qtype_key: QType,
) -> Result<Vec<SocketAddr>> {
    use crate::dns::cache::{Key, QType as CacheQType};
    let ck = Key {
        name: host.to_string(),
        qtype: match qtype_key {
            QType::A => CacheQType::A,
            QType::AAAA => CacheQType::AAAA,
            _ => return Err(anyhow::anyhow!("Unsupported query type")),
        },
    };

    // 命中缓存
    if let Some(answer) = cache.get(host) {
        #[cfg(feature = "metrics")]
        metrics::counter!("dns_cache_hit_total").increment(1);
        return Ok(answer
            .ips
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect());
    }

    // 缓存未命中，进行实际查询
    // 真正查询
    let qsel = match qtype_key {
        QType::A => QSel::A,
        QType::AAAA => QSel::AAAA,
        _ => return Err(anyhow::anyhow!("Unsupported query type")),
    };
    let res = match backend {
        DnsBackend::Auto => {
            if let Ok(v) = resolve_qsel_qtype(DnsBackend::System, qsel, host, port, timeout).await {
                v
            } else if let Ok(v) =
                resolve_qsel_qtype(DnsBackend::Udp, qsel, host, port, timeout).await
            {
                v
            } else if let Ok(v) =
                resolve_qsel_qtype(DnsBackend::Dot, qsel, host, port, timeout).await
            {
                v
            } else {
                resolve_qsel_qtype(DnsBackend::Doh, qsel, host, port, timeout).await?
            }
        }
        b => resolve_qsel_qtype(b, qsel, host, port, timeout).await?,
    };
    // 写回缓存
    if res.is_empty() {
        cache.put_negative(host);
    } else {
        // TTL：保守取 60s；如后端提供 TTL，可在 udp/dot/doh 解析处带回真实 TTL
        let ttl = std::env::var("SB_DNS_CACHE_TTL_SEC")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(60);
        let ips: Vec<std::net::IpAddr> = res.iter().map(|sa| sa.ip()).collect();
        let answer = super::DnsAnswer {
            ips,
            ttl: std::time::Duration::from_secs(ttl as u64),
            source: super::cache::Source::System,
            rcode: super::cache::Rcode::NoError,
        };
        cache.put(host, answer);
    }
    Ok(res)
}

#[cfg(feature = "dns_cache")]
async fn refresh_cached_qtype(
    cache: &'static DnsCache,
    ck: super::cache::Key,
    backend: DnsBackend,
    host: &str,
    port: u16,
    timeout: u64,
    qsel: QSel,
) -> Result<()> {
    let res = match backend {
        DnsBackend::Auto => {
            if let Ok(v) = resolve_qsel_qtype(DnsBackend::System, qsel, host, port, timeout).await {
                v
            } else if let Ok(v) =
                resolve_qsel_qtype(DnsBackend::Udp, qsel, host, port, timeout).await
            {
                v
            } else if let Ok(v) =
                resolve_qsel_qtype(DnsBackend::Dot, qsel, host, port, timeout).await
            {
                v
            } else {
                resolve_qsel_qtype(DnsBackend::Doh, qsel, host, port, timeout).await?
            }
        }
        b => resolve_qsel_qtype(b, qsel, host, port, timeout).await?,
    };
    if res.is_empty() {
        cache.put_negative(host);
    } else {
        let ttl = std::env::var("SB_DNS_CACHE_TTL_SEC")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(60);
        let ips: Vec<std::net::IpAddr> = res.iter().map(|sa| sa.ip()).collect();
        let answer = super::DnsAnswer {
            ips,
            ttl: std::time::Duration::from_secs(ttl as u64),
            source: super::cache::Source::System,
            rcode: super::cache::Rcode::NoError,
        };
        cache.put(host, answer);
    }
    Ok(())
}

#[cfg(feature = "dns_cache")]
async fn refresh<F, Fut>(
    cache: &'static DnsCache,
    ck: super::cache::Key,
    backend: DnsBackend,
    run: F,
) -> Result<()>
where
    F: Fn(DnsBackend) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<Vec<SocketAddr>>> + Send,
{
    let res = match backend {
        DnsBackend::Auto => {
            if let Ok(v) = run(DnsBackend::System).await {
                v
            } else if let Ok(v) = run(DnsBackend::Udp).await {
                v
            } else if let Ok(v) = run(DnsBackend::Dot).await {
                v
            } else {
                run(DnsBackend::Doh).await?
            }
        }
        b => run(b).await?,
    };
    if res.is_empty() {
        cache.put_negative(&ck.name);
    } else {
        let ttl = std::env::var("SB_DNS_CACHE_TTL_SEC")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or(60);
        let ips: Vec<std::net::IpAddr> = res.iter().map(|sa| sa.ip()).collect();
        let answer = super::DnsAnswer {
            ips,
            ttl: std::time::Duration::from_secs(ttl as u64),
            source: super::cache::Source::System,
            rcode: super::cache::Rcode::NoError,
        };
        cache.put(&ck.name, answer);
    }
    Ok(())
}
