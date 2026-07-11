use super::{router_build_index_from_str, spawn_rules_hot_reload, RouterIndex};
use crate::router::decision_intern::intern_decision;
use crate::runtime_options::RouterRuntimeOptions;
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
        suffix_strict: false,
        suffix_trie_enabled: false,
        rules: vec![],
    })
}

fn rules_text(options: &RouterRuntimeOptions) -> String {
    if !options.rules_inline.is_empty() {
        return options.rules_inline.clone();
    }
    options
        .rules_file
        .as_ref()
        .and_then(|path| std::fs::read_to_string(path).ok())
        .unwrap_or_default()
}

fn build_router_index_or_unresolved(text: &str, max_rules: usize) -> Arc<RouterIndex> {
    router_build_index_from_str(text, max_rules)
        .unwrap_or_else(|_| empty_router_index("unresolved"))
}

#[must_use]
pub fn shared_index_with_options(options: &RouterRuntimeOptions) -> Arc<RwLock<Arc<RouterIndex>>> {
    Arc::new(RwLock::new(build_router_index_or_unresolved(
        &rules_text(options),
        options.rules_max,
    )))
}

#[must_use]
pub fn shared_index() -> Arc<RwLock<Arc<RouterIndex>>> {
    shared_index_with_options(&RouterRuntimeOptions::default())
}

pub async fn router_index_with_reload(
    options: Arc<RouterRuntimeOptions>,
) -> Arc<RwLock<Arc<RouterIndex>>> {
    let initial = if let Some(path) = options.rules_file.as_ref() {
        tokio::fs::read_to_string(path).await.unwrap_or_default()
    } else {
        options.rules_inline.clone()
    };
    let shared = Arc::new(RwLock::new(build_router_index_or_unresolved(
        &initial,
        options.rules_max,
    )));
    let _ = spawn_rules_hot_reload(shared.clone(), options).await;
    shared
}

pub async fn router_index_from_env_with_reload() -> Arc<RwLock<Arc<RouterIndex>>> {
    router_index_with_reload(Arc::new(RouterRuntimeOptions::default())).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn options_build_isolated_indexes() {
        let first = RouterRuntimeOptions {
            rules_inline: "exact:a.example=direct\ndefault=reject".into(),
            ..RouterRuntimeOptions::default()
        };
        let second = RouterRuntimeOptions {
            rules_inline: "exact:b.example=proxy\ndefault=unresolved".into(),
            ..RouterRuntimeOptions::default()
        };
        let first = shared_index_with_options(&first);
        let second = shared_index_with_options(&second);
        assert_ne!(
            first.read().unwrap().checksum,
            second.read().unwrap().checksum
        );
    }
}
