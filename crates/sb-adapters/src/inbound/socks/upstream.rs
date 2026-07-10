//! Adapter-owned SOCKS UDP upstream session state.

use crate::outbound::socks5_udp::{UpSocksSession, UpSocksSessionConfig};
use sb_core::outbound::endpoint::{ProxyEndpoint, ProxyKind};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::time::{Duration, Instant};

#[derive(Clone, Debug)]
pub(super) struct UpstreamRuntimeConfig {
    pub(super) session: UpSocksSessionConfig,
    pub(super) max_sessions: Option<usize>,
    pub(super) foreground_receive_iterations: usize,
    pub(super) foreground_receive_timeout_ms: u64,
    pub(super) background_receive_timeout_ms: u64,
    pub(super) legacy_default_endpoint: Option<ProxyEndpoint>,
}

impl UpstreamRuntimeConfig {
    pub(super) fn from_env() -> Self {
        Self {
            session: UpSocksSessionConfig {
                background_receive: env_bool("SB_SOCKS_UDP_UP_RECV_TASK", false),
                receive_channel_capacity: env_usize("SB_SOCKS_UDP_UP_RECV_CH", 256)
                    .clamp(1, 16_384),
                observe_io: env_bool("SB_OBS_UDP_IO", false),
            },
            max_sessions: optional_env_usize("SB_UDP_UPSTREAM_MAX"),
            foreground_receive_iterations: env_usize("SB_SOCKS_UDP_UP_RECV_ITERS", 2).min(8),
            foreground_receive_timeout_ms: env_u64("SB_SOCKS_UDP_UP_RECV_MS", 200).min(2_000),
            background_receive_timeout_ms: env_u64("SB_SOCKS_UDP_UP_BG_RECV_MS", 500).min(10_000),
            legacy_default_endpoint: legacy_default_endpoint_from_env(),
        }
    }
}

fn legacy_default_endpoint_from_env() -> Option<ProxyEndpoint> {
    let mode = std::env::var("SB_UDP_PROXY_MODE").ok()?;
    if !mode.eq_ignore_ascii_case("socks5") {
        return None;
    }
    let raw = std::env::var("SB_UDP_SOCKS5_ADDR")
        .or_else(|_| std::env::var("SB_UDP_PROXY_ADDR"))
        .ok()?;
    let address = match raw.parse() {
        Ok(address) => address,
        Err(error) => {
            tracing::warn!(%error, %raw, "invalid legacy SOCKS UDP proxy address");
            return None;
        }
    };
    Some(ProxyEndpoint {
        kind: ProxyKind::Socks5,
        addr: address,
        auth: None,
        weight: 1,
        max_fail: 3,
        open_ms: 5_000,
        half_open_ms: 1_000,
    })
}

fn env_bool(name: &str, default: bool) -> bool {
    match std::env::var(name) {
        Ok(value) => value == "1" || value.eq_ignore_ascii_case("true"),
        Err(_) => default,
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    optional_env_usize(name).unwrap_or(default)
}

fn optional_env_usize(name: &str) -> Option<usize> {
    let value = std::env::var(name).ok()?;
    match value.parse::<usize>() {
        Ok(parsed) => Some(parsed),
        Err(error) => {
            tracing::warn!(%error, %value, env = name, "invalid SOCKS UDP usize env; using default");
            None
        }
    }
}

fn env_u64(name: &str, default: u64) -> u64 {
    let Ok(value) = std::env::var(name) else {
        return default;
    };
    match value.parse::<u64>() {
        Ok(parsed) => parsed,
        Err(error) => {
            tracing::warn!(%error, %value, env = name, default, "invalid SOCKS UDP u64 env");
            default
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) struct Key {
    pub(super) src: SocketAddr,
    pub(super) dst: (IpAddr, u16),
}

struct Entry {
    session: Arc<UpSocksSession>,
    last_used: Instant,
}

pub(super) struct UdpUpstreamMap {
    inner: Mutex<HashMap<Key, Entry>>,
    ttl: Duration,
    max: Option<usize>,
}

impl UdpUpstreamMap {
    pub(super) fn new(ttl: Duration, max: Option<usize>) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl,
            max,
        }
    }

    pub(super) async fn get(&self, key: &Key) -> Option<Arc<UpSocksSession>> {
        let mut guard = self.inner.lock().await;
        let entry = guard.get_mut(key)?;
        entry.last_used = Instant::now();
        Some(entry.session.clone())
    }

    pub(super) async fn insert(&self, key: Key, session: Arc<UpSocksSession>) -> bool {
        let mut guard = self.inner.lock().await;
        if self
            .max
            .is_some_and(|max| !guard.contains_key(&key) && guard.len() >= max)
        {
            #[cfg(feature = "metrics")]
            metrics::counter!("udp_upstream_error_total", "class" => "capacity").increment(1);
            return false;
        }
        #[cfg(feature = "metrics")]
        let is_new = !guard.contains_key(&key);
        guard.insert(
            key,
            Entry {
                session,
                last_used: Instant::now(),
            },
        );
        #[cfg(feature = "metrics")]
        {
            if is_new {
                metrics::counter!("udp_upstream_map_create_total").increment(1);
            }
            metrics::gauge!("udp_upstream_map_size").set(guard.len() as f64);
        }
        true
    }

    pub(super) async fn evict_expired(&self) -> usize {
        let mut guard = self.inner.lock().await;
        let before = guard.len();
        let ttl = self.ttl;
        guard.retain(|_, entry| entry.last_used.elapsed() < ttl);
        let removed = before.saturating_sub(guard.len());
        if removed > 0 {
            #[cfg(feature = "metrics")]
            {
                metrics::counter!("udp_upstream_map_evict_total").increment(removed as u64);
                metrics::gauge!("udp_upstream_map_size").set(guard.len() as f64);
            }
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    struct EnvSnapshot(Vec<(&'static str, Option<OsString>)>);

    impl EnvSnapshot {
        fn capture(keys: &'static [&'static str]) -> Self {
            Self(
                keys.iter()
                    .map(|key| (*key, std::env::var_os(key)))
                    .collect(),
            )
        }
    }

    impl Drop for EnvSnapshot {
        fn drop(&mut self) {
            for (key, value) in self.0.drain(..) {
                match value {
                    Some(value) => std::env::set_var(key, value),
                    None => std::env::remove_var(key),
                }
            }
        }
    }

    #[test]
    fn defaults_preserve_legacy_receive_behavior() {
        let config = UpSocksSessionConfig::default();
        assert!(!config.background_receive);
        assert_eq!(config.receive_channel_capacity, 256);
        assert!(!config.observe_io);
    }

    #[test]
    #[serial_test::serial]
    fn runtime_config_freezes_and_clamps_legacy_env() {
        const KEYS: &[&str] = &[
            "SB_SOCKS_UDP_UP_RECV_TASK",
            "SB_SOCKS_UDP_UP_RECV_CH",
            "SB_OBS_UDP_IO",
            "SB_UDP_UPSTREAM_MAX",
            "SB_SOCKS_UDP_UP_RECV_ITERS",
            "SB_SOCKS_UDP_UP_RECV_MS",
            "SB_SOCKS_UDP_UP_BG_RECV_MS",
            "SB_UDP_PROXY_MODE",
            "SB_UDP_SOCKS5_ADDR",
            "SB_UDP_PROXY_ADDR",
        ];
        let _snapshot = EnvSnapshot::capture(KEYS);
        std::env::set_var("SB_SOCKS_UDP_UP_RECV_TASK", "true");
        std::env::set_var("SB_SOCKS_UDP_UP_RECV_CH", "20000");
        std::env::set_var("SB_OBS_UDP_IO", "1");
        std::env::set_var("SB_UDP_UPSTREAM_MAX", "17");
        std::env::set_var("SB_SOCKS_UDP_UP_RECV_ITERS", "99");
        std::env::set_var("SB_SOCKS_UDP_UP_RECV_MS", "9999");
        std::env::set_var("SB_SOCKS_UDP_UP_BG_RECV_MS", "99999");
        std::env::set_var("SB_UDP_PROXY_MODE", "SOCKS5");
        std::env::set_var("SB_UDP_SOCKS5_ADDR", "127.0.0.1:1081");
        std::env::set_var("SB_UDP_PROXY_ADDR", "127.0.0.1:1082");

        let config = UpstreamRuntimeConfig::from_env();
        std::env::set_var("SB_SOCKS_UDP_UP_RECV_CH", "1");

        assert!(config.session.background_receive);
        assert_eq!(config.session.receive_channel_capacity, 16_384);
        assert!(config.session.observe_io);
        assert_eq!(config.max_sessions, Some(17));
        assert_eq!(config.foreground_receive_iterations, 8);
        assert_eq!(config.foreground_receive_timeout_ms, 2_000);
        assert_eq!(config.background_receive_timeout_ms, 10_000);
        assert_eq!(
            config
                .legacy_default_endpoint
                .expect("legacy endpoint")
                .addr,
            "127.0.0.1:1081".parse().unwrap()
        );
    }
}
