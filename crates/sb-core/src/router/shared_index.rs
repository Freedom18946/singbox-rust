use super::{
    router_build_index_from_str, router_rules_max_from_env, spawn_rules_hot_reload, RouterIndex,
};
use crate::router::decision_intern::intern_decision;
use once_cell::sync::Lazy;
use std::sync::{Arc, RwLock};

pub(crate) fn empty_router_index(default: &str) -> Arc<RouterIndex> {
    Arc::new(RouterIndex {
        exact: Default::default(),
        suffix: vec![],
        suffix_map: Default::default(),
        port_rules: Default::default(),
        port_ranges: vec![],
        transport_tcp: None,
        transport_udp: None,
        cidr4: vec![],
        cidr6: vec![],
        cidr4_buckets: vec![Vec::new(); 33],
        cidr6_buckets: vec![Vec::new(); 129],
        geoip_rules: vec![],
        geosite_rules: vec![],
        wifi_ssid_rules: Default::default(),
        wifi_bssid_rules: Default::default(),
        rule_set_rules: Default::default(),
        process_rules: Default::default(),
        process_path_rules: Default::default(),
        protocol_rules: Default::default(),
        network_rules: Default::default(),
        source_rules: vec![],
        dest_rules: vec![],
        user_agent_rules: vec![],
        #[cfg(feature = "router_keyword")]
        keyword_rules: vec![],
        #[cfg(feature = "router_keyword")]
        keyword_idx: None,
        default: intern_decision(default),
        gen: 0,
        checksum: [0; 32],
        rules: vec![],
    })
}

fn router_rules_from_env_sync() -> String {
    let inline = std::env::var("SB_ROUTER_RULES").unwrap_or_default();
    if inline.is_empty() {
        if let Ok(path) = std::env::var("SB_ROUTER_RULES_FILE") {
            std::fs::read_to_string(path).unwrap_or_default()
        } else {
            String::new()
        }
    } else {
        inline
    }
}

fn build_router_index_or_unresolved(text: &str, max_rules: usize) -> Arc<RouterIndex> {
    router_build_index_from_str(text, max_rules)
        .unwrap_or_else(|_| empty_router_index("unresolved"))
}

fn load_router_index_from_env_sync() -> Arc<RouterIndex> {
    let max_rules = router_rules_max_from_env();
    let text = router_rules_from_env_sync();
    build_router_index_or_unresolved(&text, max_rules)
}

pub(crate) fn shared_hot_reload_enabled_from_env() -> bool {
    let file = std::env::var("SB_ROUTER_RULES_FILE").unwrap_or_default();
    !file.is_empty() && super::router_rules_hot_reload_ms_from_env() > 0
}

pub async fn router_index_from_env_with_reload() -> Arc<RwLock<Arc<RouterIndex>>> {
    let max_rules = router_rules_max_from_env();
    let init_rules = if let Ok(path) = std::env::var("SB_ROUTER_RULES_FILE") {
        tokio::fs::read_to_string(&path).await.unwrap_or_default()
    } else {
        std::env::var("SB_ROUTER_RULES").unwrap_or_default()
    };
    let idx = build_router_index_or_unresolved(&init_rules, max_rules);
    let shared = Arc::new(RwLock::new(idx));
    let _ = spawn_rules_hot_reload(shared.clone()).await;
    shared
}

static SHARED_INDEX: Lazy<Arc<RwLock<Arc<RouterIndex>>>> =
    Lazy::new(|| Arc::new(RwLock::new(load_router_index_from_env_sync())));

static SHARED_INDEX_ENV_CACHE: Lazy<RwLock<Option<String>>> = Lazy::new(|| RwLock::new(None));

fn refresh_shared_index_from_env_if_needed() {
    let max_rules = router_rules_max_from_env();
    let inline = std::env::var("SB_ROUTER_RULES").unwrap_or_default();
    let file = std::env::var("SB_ROUTER_RULES_FILE").unwrap_or_default();

    let key = format!("max_rules={max_rules}\nfile={file}\ninline={inline}");
    {
        let mut cache = SHARED_INDEX_ENV_CACHE
            .write()
            .unwrap_or_else(|e| e.into_inner());
        if cache.as_deref() == Some(&key) {
            return;
        }
        *cache = Some(key);
    }

    let idx = load_router_index_from_env_sync();
    let mut shared = SHARED_INDEX.write().unwrap_or_else(|e| e.into_inner());
    *shared = idx;
}

pub fn shared_index() -> Arc<RwLock<Arc<RouterIndex>>> {
    refresh_shared_index_from_env_if_needed();
    if tokio::runtime::Handle::try_current().is_ok() && shared_hot_reload_enabled_from_env() {
        static STARTED: Lazy<std::sync::Once> = Lazy::new(std::sync::Once::new);
        STARTED.call_once(|| {
            let shared = SHARED_INDEX.clone();
            tokio::spawn(async move {
                let _ = spawn_rules_hot_reload(shared).await;
            });
        });
    }
    SHARED_INDEX.clone()
}
