use std::sync::Arc;

pub(crate) fn create_router_handle() -> Arc<sb_core::router::engine::RouterHandle> {
    use sb_core::router::dns_integration::setup_dns_routing;

    Arc::new(setup_dns_routing())
}

pub(crate) fn parse_env_usize(key: &str, default: usize) -> usize {
    let raw = match std::env::var(key) {
        Ok(value) => value,
        Err(_) => return default,
    };
    let trimmed = raw.trim();
    match trimmed.parse::<usize>() {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(
                "env '{key}' value '{trimmed}' is not a valid usize; silent parse fallback is disabled; using default {default}: {error}"
            );
            default
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};

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
    fn parse_env_usize_accepts_trimmed_numbers_and_falls_back_on_invalid_values() {
        let _guard = env_lock().lock().expect("env lock");
        let _restore = EnvGuard::new(&["SB_ROUTER_RULES_MAX"]);

        std::env::set_var("SB_ROUTER_RULES_MAX", " 512 ");
        assert_eq!(parse_env_usize("SB_ROUTER_RULES_MAX", 100), 512);

        std::env::set_var("SB_ROUTER_RULES_MAX", "not-a-number");
        assert_eq!(parse_env_usize("SB_ROUTER_RULES_MAX", 100), 100);
    }

    #[test]
    fn create_router_handle_smoke_builds_dns_integrated_handle() {
        let handle = create_router_handle();
        let debug = format!("{handle:?}");

        assert!(debug.contains("RouterHandle"));
    }

    #[test]
    fn wp30an_pin_router_helpers_owner_lives_in_bootstrap_runtime() {
        let source = include_str!("router_helpers.rs");
        let bootstrap = include_str!("../bootstrap.rs");

        assert!(source.contains("pub(crate) fn create_router_handle()"));
        assert!(source.contains("pub(crate) fn parse_env_usize("));
        assert!(!bootstrap.contains("fn create_router_handle()"));
        assert!(!bootstrap.contains("fn parse_env_usize("));
        assert!(
            bootstrap.contains("crate::bootstrap_runtime::router_helpers::create_router_handle()")
        );
        assert!(bootstrap.contains("crate::bootstrap_runtime::router_helpers::parse_env_usize("));
    }
}
