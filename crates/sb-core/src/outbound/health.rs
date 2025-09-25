use crate::outbound::endpoint::{ProxyEndpoint, ProxyKind};
use crate::outbound::registry;
#[cfg(feature = "metrics")]
use crate::telemetry::error_class;
use dashmap::DashMap;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Clone)]
pub struct HealthStatus {
    pub up: Arc<AtomicBool>,
    pub last_rtt_ms: Arc<parking_lot::Mutex<Option<u64>>>,
    pub consecutive_fail: Arc<parking_lot::Mutex<u32>>,
    pub last_check: Arc<parking_lot::Mutex<Option<Instant>>>,
}

impl HealthStatus {
    pub fn new() -> Self {
        Self {
            up: Arc::new(AtomicBool::new(true)), // Default to up
            last_rtt_ms: Arc::new(parking_lot::Mutex::new(None)),
            consecutive_fail: Arc::new(parking_lot::Mutex::new(0)),
            last_check: Arc::new(parking_lot::Mutex::new(None)),
        }
    }

    pub fn is_up(&self) -> bool {
        self.up.load(Ordering::Relaxed)
    }
}

pub struct EpState {
    pub up: AtomicBool,
    pub consecutive_fail: parking_lot::Mutex<u32>,
    pub opened_at: parking_lot::Mutex<Option<Instant>>, // Circuit breaker open time
    pub last_rtt_ms: parking_lot::Mutex<Option<u64>>,
}

static STATUS: once_cell::sync::OnceCell<HealthStatus> = once_cell::sync::OnceCell::new();
static STATES: once_cell::sync::OnceCell<DashMap<String, EpState>> =
    once_cell::sync::OnceCell::new(); // key: "name#index"

pub struct MultiHealthView;

// NOTE: HealthView trait can be wired when multi-pool selection is finalized.
/*impl crate::outbound::selector::HealthView for MultiHealthView {
    fn is_selectable(&self, ep: &ProxyEndpoint) -> bool {
        let states = match STATES.get() {
            Some(s) => s,
            None => return true, // No health system initialized, assume healthy
        };

        // Construct key (simplified: use addr as key; for named pools, registration should maintain "pool:name#idx")
        let k = format!("{}", ep.addr);
        if let Some(s) = states.get(&k) {
            if !s.up.load(Ordering::Relaxed) {
                // Check circuit breaker window
                if let Some(t0) = *s.opened_at.lock() {
                    if t0.elapsed() < Duration::from_millis(ep.open_ms) {
                        return false;
                    }
                }
            }
        }
        true
    }
}*/

pub fn global_status() -> Option<&'static HealthStatus> {
    STATUS.get()
}

pub async fn spawn_if_enabled() {
    if !enabled() {
        return;
    }
    let registry = registry::global();
    if registry.is_none() {
        return;
    }
    let st = STATUS.get_or_init(HealthStatus::new).clone();
    let _ = STATES.get_or_init(|| DashMap::new());
    let interval_ms = interval_ms();

    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(interval_ms)).await;
            if let Some(reg) = registry::global() {
                // Check default endpoint
                if let Some(ep) = reg.default.clone() {
                    let _ = one_check(&st, &ep).await;
                    let _ = one_check_ep("default", &ep).await;
                }
                // Check pool endpoints
                for (_name, pool) in reg.pools.iter() {
                    for (i, ep) in pool.endpoints.iter().enumerate() {
                        let key = format!("{}#{}", pool.name, i);
                        let _ = one_check_ep(&key, ep).await;
                    }
                }
            }
        }
    });
}

async fn one_check(st: &HealthStatus, ep: &ProxyEndpoint) -> anyhow::Result<()> {
    let t0 = Instant::now();
    let check_result = match ep.kind {
        ProxyKind::Http => check_http(ep.clone()).await,
        ProxyKind::Socks5 => check_socks5(ep.clone()).await,
    };

    *st.last_check.lock() = Some(Instant::now());

    match check_result {
        Ok(_) => {
            st.up.store(true, Ordering::Relaxed);
            *st.consecutive_fail.lock() = 0;
            *st.last_rtt_ms.lock() = Some(t0.elapsed().as_millis() as u64);

            #[cfg(feature = "metrics")]
            {
                metrics::gauge!("proxy_up", "kind" => label(ep.kind)).set(1.0);
                metrics::histogram!("proxy_rtt_seconds", "kind" => label(ep.kind))
                    .record(t0.elapsed().as_secs_f64());
                metrics::counter!("proxy_check_total", "result" => "ok", "kind" => label(ep.kind))
                    .increment(1);
            }
        }
        Err(err) => {
            st.up.store(false, Ordering::Relaxed);
            let mut c = st.consecutive_fail.lock();
            *c = c.saturating_add(1);

            #[cfg(feature = "metrics")]
            {
                metrics::gauge!("proxy_up", "kind" => label(ep.kind)).set(0.0);

                // Use error classification instead of generic "fail"
                let error_class = if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
                    error_class::classify_io(io_err)
                } else {
                    error_class::classify_proto(err.as_ref())
                };

                metrics::counter!("proxy_check_total", "result" => "fail", "class" => error_class, "kind" => label(ep.kind))
                    .increment(1);
            }
        }
    }
    Ok(())
}

async fn one_check_ep(key: &str, ep: &ProxyEndpoint) -> anyhow::Result<()> {
    let t0 = Instant::now();
    let check_result = match ep.kind {
        ProxyKind::Http => check_http(ep.clone()).await,
        ProxyKind::Socks5 => check_socks5(ep.clone()).await,
    };

    let states = STATES.get().unwrap();
    let ent = states.entry(key.to_string()).or_insert_with(|| EpState {
        up: AtomicBool::new(true),
        consecutive_fail: parking_lot::Mutex::new(0),
        opened_at: parking_lot::Mutex::new(None),
        last_rtt_ms: parking_lot::Mutex::new(None),
    });

    match check_result {
        Ok(_) => {
            ent.up.store(true, Ordering::Relaxed);
            *ent.consecutive_fail.lock() = 0;
            *ent.opened_at.lock() = None;
            *ent.last_rtt_ms.lock() = Some(t0.elapsed().as_millis() as u64);

            #[cfg(feature = "metrics")]
            {
                metrics::gauge!("proxy_up", "kind" => label(ep.kind), "endpoint" => key.to_string()).set(1.0);
                metrics::histogram!("proxy_rtt_seconds", "kind" => label(ep.kind), "endpoint" => key.to_string())
                    .record(t0.elapsed().as_secs_f64());
                metrics::counter!("proxy_check_total", "result" => "ok", "kind" => label(ep.kind), "endpoint" => key.to_string())
                    .increment(1);
            }
        }
        Err(err) => {
            ent.up.store(false, Ordering::Relaxed);
            let mut c = ent.consecutive_fail.lock();
            *c = c.saturating_add(1);
            if *c >= ep.max_fail.max(1) {
                *ent.opened_at.lock() = Some(Instant::now());
            }

            #[cfg(feature = "metrics")]
            {
                metrics::gauge!("proxy_up", "kind" => label(ep.kind), "endpoint" => key.to_string()).set(0.0);

                // Use error classification instead of generic "fail"
                let error_class = if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
                    error_class::classify_io(io_err)
                } else {
                    error_class::classify_proto(err.as_ref())
                };

                metrics::counter!("proxy_check_total", "result" => "fail", "class" => error_class, "kind" => label(ep.kind), "endpoint" => key.to_string())
                    .increment(1);

                if *c >= ep.max_fail.max(1) {
                    metrics::counter!("proxy_circuit_state_total", "endpoint" => key.to_string(), "state" => "open")
                        .increment(1);
                }
            }
        }
    }
    Ok(())
}

async fn check_http(ep: ProxyEndpoint) -> anyhow::Result<()> {
    use anyhow::Context;
    let mut s = TcpStream::connect(ep.addr).await.context("tcp connect")?;

    // Send minimal CONNECT test to example.com:80, successful 2xx response indicates health
    let req = b"CONNECT example.com:80 HTTP/1.1\r\nHost: example.com:80\r\n\r\n";
    s.write_all(req).await?;

    let mut buf = [0u8; 128];
    let n = tokio::time::timeout(Duration::from_millis(timeout_ms()), s.read(&mut buf)).await??;

    // Parse HTTP response line properly instead of using magic indices
    let response = std::str::from_utf8(&buf[..n]).unwrap_or("");
    if let Some(line_end) = response.find("\r\n") {
        let status_line = &response[..line_end];

        // Match HTTP/1.[01] <status> pattern
        if let Some(parts) = parse_http_status_line(status_line) {
            let (version, status_code) = parts;
            if version == "HTTP/1.0" || version == "HTTP/1.1" {
                // 2xx (success) or 407 (proxy auth required - indicates connectivity) = healthy
                if (status_code >= 200 && status_code < 300) || status_code == 407 {
                    return Ok(());
                }
            }
        }
    }

    Err(anyhow::anyhow!("http proxy bad response"))
}

fn parse_http_status_line(line: &str) -> Option<(&str, u16)> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() >= 2 {
        let version = parts[0];
        if let Ok(status) = parts[1].parse::<u16>() {
            return Some((version, status));
        }
    }
    None
}

async fn check_socks5(ep: ProxyEndpoint) -> anyhow::Result<()> {
    use anyhow::Context;
    let mut s = TcpStream::connect(ep.addr).await.context("tcp connect")?;

    // SOCKS5 method selection: NOAUTH
    s.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut buf = [0u8; 2];
    tokio::time::timeout(Duration::from_millis(timeout_ms()), s.read_exact(&mut buf)).await??;

    if buf == [0x05, 0x00] {
        return Ok(());
    }
    Err(anyhow::anyhow!("socks5 method negotiation failed"))
}

fn enabled() -> bool {
    std::env::var("SB_PROXY_HEALTH_ENABLE")
        .ok()
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn interval_ms() -> u64 {
    std::env::var("SB_PROXY_HEALTH_INTERVAL_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(3000)
}

fn timeout_ms() -> u64 {
    std::env::var("SB_PROXY_HEALTH_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(800)
}

fn label(k: ProxyKind) -> &'static str {
    match k {
        ProxyKind::Http => "http",
        ProxyKind::Socks5 => "socks5",
    }
}
