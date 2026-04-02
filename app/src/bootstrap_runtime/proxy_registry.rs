use anyhow::Result;
use sb_core::outbound::{endpoint::ProxyEndpoint, registry as ob_registry};
use std::collections::HashMap;

pub(crate) struct ProxyRegistryPlan {
    registry: Option<ob_registry::Registry>,
}

impl ProxyRegistryPlan {
    pub fn from_env() -> Result<Self> {
        let pools = load_pools_from_env()?;
        let registry = std::env::var("SB_ROUTER_DEFAULT_PROXY")
            .ok()
            .and_then(|value| ProxyEndpoint::parse(&value))
            .map(|endpoint| ob_registry::Registry {
                default: Some(ProxyEndpoint {
                    weight: 1,
                    max_fail: 3,
                    open_ms: 5000,
                    half_open_ms: 1000,
                    ..endpoint
                }),
                pools: pools.clone(),
            });

        Ok(Self { registry })
    }

    #[must_use]
    pub fn is_configured(&self) -> bool {
        self.registry.is_some()
    }

    pub fn install(self) {
        if let Some(registry) = self.registry {
            ob_registry::install_global(registry);
        }
    }
}

pub(crate) fn init_proxy_registry_from_env() {
    match ProxyRegistryPlan::from_env() {
        Ok(plan) => plan.install(),
        Err(error) => {
            tracing::warn!(error = %error, "failed to load proxy registry from env; skipping install");
        }
    }
}

pub(crate) fn load_pools_from_env() -> Result<HashMap<String, ob_registry::ProxyPool>> {
    use std::fs;

    if let Ok(text) = std::env::var("SB_PROXY_POOL_JSON") {
        return parse_pool_json(&text);
    }
    if let Ok(path) = std::env::var("SB_PROXY_POOL_FILE") {
        let text = fs::read_to_string(path)?;
        return parse_pool_json(&text);
    }
    Ok(HashMap::new())
}

pub(crate) fn parse_pool_json(txt: &str) -> Result<HashMap<String, ob_registry::ProxyPool>> {
    use sb_core::outbound::{
        endpoint::ProxyKind,
        registry::{PoolPolicy, ProxyPool, StickyCfg},
    };

    #[derive(serde::Deserialize)]
    struct EndpointDoc {
        kind: String,
        addr: String,
        weight: Option<u32>,
        max_fail: Option<u32>,
        open_ms: Option<u64>,
        half_open_ms: Option<u64>,
    }

    #[derive(serde::Deserialize)]
    struct PoolDoc {
        name: String,
        policy: Option<String>,
        sticky_ttl_ms: Option<u64>,
        sticky_cap: Option<usize>,
        endpoints: Vec<EndpointDoc>,
    }

    let pools: Vec<PoolDoc> = serde_json::from_str(txt)?;
    let mut map = HashMap::new();

    for pool in pools {
        let endpoints = pool
            .endpoints
            .into_iter()
            .filter_map(|endpoint| {
                let kind = match endpoint.kind.to_ascii_lowercase().as_str() {
                    "http" => ProxyKind::Http,
                    "socks5" => ProxyKind::Socks5,
                    _ => return None,
                };
                let addr = endpoint.addr.parse().ok()?;
                Some(ProxyEndpoint {
                    kind,
                    addr,
                    auth: None,
                    weight: endpoint.weight.unwrap_or(1),
                    max_fail: endpoint.max_fail.unwrap_or(3),
                    open_ms: endpoint.open_ms.unwrap_or(5000),
                    half_open_ms: endpoint.half_open_ms.unwrap_or(1000),
                })
            })
            .collect();

        let proxy_pool = ProxyPool {
            name: pool.name.clone(),
            endpoints,
            policy: match pool.policy.as_deref() {
                Some("latency_bias") => PoolPolicy::WeightedRRWithLatencyBias,
                _ => PoolPolicy::WeightedRR,
            },
            sticky: StickyCfg {
                ttl_ms: pool.sticky_ttl_ms.unwrap_or(10_000),
                cap: pool.sticky_cap.unwrap_or(4096),
            },
        };
        map.insert(pool.name, proxy_pool);
    }

    Ok(map)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_core::outbound::{endpoint::ProxyKind, registry::PoolPolicy};
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    use tempfile::NamedTempFile;

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    struct EnvGuard {
        saved: HashMap<&'static str, Option<String>>,
    }

    impl EnvGuard {
        fn new(keys: &[&'static str]) -> Self {
            let saved = keys
                .iter()
                .map(|key| (*key, std::env::var(key).ok()))
                .collect();
            Self { saved }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (key, value) in &self.saved {
                if let Some(value) = value {
                    std::env::set_var(key, value);
                } else {
                    std::env::remove_var(key);
                }
            }
        }
    }

    #[test]
    fn parse_pool_json_keeps_supported_endpoints_and_defaults() -> anyhow::Result<()> {
        let pools = parse_pool_json(
            r#"
            [
              {
                "name": "primary",
                "policy": "latency_bias",
                "sticky_ttl_ms": 2500,
                "sticky_cap": 64,
                "endpoints": [
                  {"kind": "http", "addr": "127.0.0.1:8080", "weight": 4},
                  {"kind": "socks5", "addr": "127.0.0.1:1080"},
                  {"kind": "ftp", "addr": "127.0.0.1:21"}
                ]
              }
            ]
            "#,
        )?;

        let pool = pools.get("primary").expect("pool should exist");
        assert_eq!(pool.endpoints.len(), 2);
        assert!(matches!(pool.endpoints[0].kind, ProxyKind::Http));
        assert_eq!(pool.endpoints[0].weight, 4);
        assert!(matches!(pool.endpoints[1].kind, ProxyKind::Socks5));
        assert_eq!(pool.endpoints[1].weight, 1);
        assert!(matches!(pool.policy, PoolPolicy::WeightedRRWithLatencyBias));
        assert_eq!(pool.sticky.ttl_ms, 2500);
        assert_eq!(pool.sticky.cap, 64);

        Ok(())
    }

    #[test]
    fn load_pools_from_env_prefers_inline_json_over_file() -> anyhow::Result<()> {
        let _guard = env_lock().lock().expect("env lock");
        let _restore = EnvGuard::new(&["SB_PROXY_POOL_JSON", "SB_PROXY_POOL_FILE"]);
        let file = NamedTempFile::new()?;
        std::fs::write(file.path(), "this is not json")?;

        std::env::set_var("SB_PROXY_POOL_FILE", file.path());
        std::env::set_var(
            "SB_PROXY_POOL_JSON",
            r#"[{"name":"inline","endpoints":[{"kind":"http","addr":"127.0.0.1:8080"}]}]"#,
        );

        let pools = load_pools_from_env()?;
        assert!(pools.contains_key("inline"));

        Ok(())
    }

    #[test]
    fn load_pools_from_env_reads_file_when_inline_json_is_absent() -> anyhow::Result<()> {
        let _guard = env_lock().lock().expect("env lock");
        let _restore = EnvGuard::new(&["SB_PROXY_POOL_JSON", "SB_PROXY_POOL_FILE"]);
        let file = NamedTempFile::new()?;
        std::fs::write(
            file.path(),
            r#"[{"name":"from-file","endpoints":[{"kind":"socks5","addr":"127.0.0.1:1080"}]}]"#,
        )?;

        std::env::remove_var("SB_PROXY_POOL_JSON");
        std::env::set_var("SB_PROXY_POOL_FILE", file.path());

        let pools = load_pools_from_env()?;
        let pool = pools
            .get("from-file")
            .expect("file-backed pool should exist");
        assert_eq!(pool.endpoints.len(), 1);

        Ok(())
    }

    #[test]
    fn proxy_registry_plan_collects_registry_before_install() -> anyhow::Result<()> {
        let _guard = env_lock().lock().expect("env lock");
        let _restore = EnvGuard::new(&["SB_ROUTER_DEFAULT_PROXY", "SB_PROXY_POOL_JSON"]);
        std::env::set_var("SB_ROUTER_DEFAULT_PROXY", "http://127.0.0.1:8080");
        std::env::set_var(
            "SB_PROXY_POOL_JSON",
            r#"[{"name":"inline","endpoints":[{"kind":"http","addr":"127.0.0.1:8080"}]}]"#,
        );

        let plan = ProxyRegistryPlan::from_env()?;
        assert!(plan.is_configured());

        Ok(())
    }

    #[test]
    fn wp30an_pin_proxy_registry_owner_lives_in_bootstrap_runtime() {
        let source = include_str!("proxy_registry.rs");
        let bootstrap = include_str!("../bootstrap.rs");

        assert!(source.contains("struct ProxyRegistryPlan"));
        assert!(source.contains("pub(crate) fn init_proxy_registry_from_env()"));
        assert!(source.contains("pub(crate) fn load_pools_from_env()"));
        assert!(source.contains("pub(crate) fn parse_pool_json("));
        assert!(!bootstrap.contains("fn init_proxy_registry_from_env()"));
        assert!(!bootstrap.contains("fn load_pools_from_env("));
        assert!(!bootstrap.contains("fn parse_pool_json("));
        assert!(bootstrap.contains("ProxyRegistryPlan::from_env()"));
    }
}
