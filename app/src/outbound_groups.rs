//! Runtime-side selector/urltest second-pass binding for the legacy bootstrap
//! path.
//!
//! This module is a runtime owner, not a planned consumer owner: it constructs
//! connectors, starts URLTest health checks, and depends on runtime services.

#[cfg(feature = "router")]
use sb_core::outbound::selector_group::{
    ProxyMember as GroupMember, SelectorGroup, UrlTestOptions,
};
#[cfg(feature = "router")]
use sb_core::outbound::Outbound as AdapterConnector;
#[cfg(feature = "router")]
use sb_core::outbound::OutboundImpl;
#[cfg(feature = "router")]
use std::{collections::HashMap, sync::Arc};
#[cfg(feature = "router")]
use tokio::time::Duration;

#[cfg(feature = "router")]
const DEFAULT_URLTEST_URL: &str = "https://www.gstatic.com/generate_204";
#[cfg(feature = "router")]
const DEFAULT_URLTEST_INTERVAL_MS: u64 = 180_000;
#[cfg(feature = "router")]
const DEFAULT_URLTEST_TIMEOUT_MS: u64 = 15_000;
#[cfg(feature = "router")]
const DEFAULT_URLTEST_TOLERANCE_MS: u64 = 50;

#[cfg(feature = "router")]
pub(crate) fn bind_selector_outbound_groups(
    ir: &sb_config::ir::ConfigIR,
    map: &mut HashMap<String, OutboundImpl>,
    cache_file: Option<Arc<dyn sb_core::context::CacheFile>>,
    urltest_history: Arc<dyn sb_core::context::URLTestHistoryStorage>,
) {
    let mut existing = map.clone();

    for ob in &ir.outbounds {
        let name = match &ob.name {
            Some(n) if !n.is_empty() => n.clone(),
            _ => continue,
        };

        match ob.ty {
            sb_config::ir::OutboundType::Selector => {
                let members = match &ob.members {
                    Some(v) if !v.is_empty() => v.as_slice(),
                    _ => {
                        tracing::warn!(selector = %name, "selector has no members; skipping");
                        continue;
                    }
                };
                let group_members = collect_group_members(&name, members, &existing);
                if group_members.is_empty() {
                    tracing::warn!(selector = %name, "no usable members; skipping selector");
                    continue;
                }
                let selector = Arc::new(SelectorGroup::new_manual(
                    name.clone(),
                    group_members,
                    ob.default_member.clone(),
                    cache_file.clone(),
                    Some(urltest_history.clone()),
                ));
                map.insert(name.clone(), OutboundImpl::Connector(selector.clone()));
                existing.insert(name, OutboundImpl::Connector(selector));
            }
            sb_config::ir::OutboundType::UrlTest => {
                let members = match &ob.members {
                    Some(v) if !v.is_empty() => v.as_slice(),
                    _ => {
                        tracing::warn!(selector = %name, "urltest has no members; skipping");
                        continue;
                    }
                };
                let group_members = collect_group_members(&name, members, &existing);
                if group_members.is_empty() {
                    tracing::warn!(selector = %name, "no usable members; skipping urltest selector");
                    continue;
                }
                let selector = Arc::new(SelectorGroup::new_urltest(
                    name.clone(),
                    group_members,
                    UrlTestOptions {
                        test_url: ob
                            .test_url
                            .clone()
                            .unwrap_or_else(|| DEFAULT_URLTEST_URL.to_string()),
                        interval: Duration::from_millis(
                            ob.test_interval_ms.unwrap_or(DEFAULT_URLTEST_INTERVAL_MS),
                        ),
                        timeout: Duration::from_millis(
                            ob.test_timeout_ms.unwrap_or(DEFAULT_URLTEST_TIMEOUT_MS),
                        ),
                        tolerance_ms: ob.test_tolerance_ms.unwrap_or(DEFAULT_URLTEST_TOLERANCE_MS),
                        cache_file: cache_file.clone(),
                        urltest_history: Some(urltest_history.clone()),
                    },
                ));
                if tokio::runtime::Handle::try_current().is_ok() {
                    selector.clone().start_health_check();
                }
                map.insert(name.clone(), OutboundImpl::Connector(selector.clone()));
                existing.insert(name, OutboundImpl::Connector(selector));
            }
            _ => {}
        }
    }
}

#[cfg(feature = "router")]
fn collect_group_members(
    selector_name: &str,
    members: &[String],
    existing: &HashMap<String, OutboundImpl>,
) -> Vec<GroupMember> {
    let mut group_members = Vec::new();

    for member in members {
        match existing.get(member) {
            Some(impl_ref) => {
                if let Some(conn) = to_adapter_connector(impl_ref) {
                    group_members.push(GroupMember::new(member.clone(), conn));
                } else {
                    tracing::warn!(
                        member = %member,
                        selector = %selector_name,
                        "member outbound cannot be used as connector; skipping"
                    );
                }
            }
            None => {
                tracing::warn!(
                    member = %member,
                    selector = %selector_name,
                    "member outbound not found"
                );
            }
        }
    }

    group_members
}

#[cfg(feature = "router")]
fn to_adapter_connector(implementation: &OutboundImpl) -> Option<Arc<dyn AdapterConnector>> {
    let OutboundImpl::Connector(connector) = implementation;
    Some(connector.clone())
}

#[cfg(all(test, feature = "router"))]
mod tests {
    use super::*;
    use sb_core::outbound::OutboundImpl;

    fn history_service() -> Arc<dyn sb_core::context::URLTestHistoryStorage> {
        Arc::new(sb_core::services::urltest_history::URLTestHistoryService::new())
    }

    fn direct_outbound(name: &str) -> sb_config::ir::OutboundIR {
        sb_config::ir::OutboundIR {
            ty: sb_config::ir::OutboundType::Direct,
            name: Some(name.to_string()),
            ..Default::default()
        }
    }

    fn selector_outbound(name: &str, members: Option<Vec<&str>>) -> sb_config::ir::OutboundIR {
        sb_config::ir::OutboundIR {
            ty: sb_config::ir::OutboundType::Selector,
            name: Some(name.to_string()),
            members: members.map(|items| items.into_iter().map(str::to_string).collect()),
            default_member: Some("direct-a".to_string()),
            ..Default::default()
        }
    }

    fn urltest_outbound(name: &str, members: Option<Vec<&str>>) -> sb_config::ir::OutboundIR {
        sb_config::ir::OutboundIR {
            ty: sb_config::ir::OutboundType::UrlTest,
            name: Some(name.to_string()),
            members: members.map(|items| items.into_iter().map(str::to_string).collect()),
            test_url: Some("https://example.com/test".to_string()),
            test_interval_ms: Some(10_000),
            test_timeout_ms: Some(3_000),
            test_tolerance_ms: Some(40),
            ..Default::default()
        }
    }

    #[derive(Debug)]
    struct TestOutbound(&'static str);

    impl sb_types::Outbound for TestOutbound {
        fn r#type(&self) -> &str {
            self.0
        }
        fn tag(&self) -> sb_types::OutboundTag {
            sb_types::OutboundTag::new(self.0)
        }
        fn network(&self) -> &[sb_types::NetworkKind] {
            &[sb_types::NetworkKind::Tcp]
        }
        fn dial<'a>(
            &'a self,
            _session: &'a sb_types::Session,
        ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedStream, sb_types::CoreError>> {
            Box::pin(async { Err(sb_types::CoreError::policy("test outbound")) })
        }
        fn listen_packet<'a>(
            &'a self,
            _session: &'a sb_types::Session,
        ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedPacketConn, sb_types::CoreError>>
        {
            Box::pin(async { Err(sb_types::CoreError::policy("test outbound")) })
        }
    }

    fn connector_impl(kind: &'static str) -> OutboundImpl {
        OutboundImpl::Connector(Arc::new(TestOutbound(kind)))
    }

    #[test]
    fn selector_binding_registers_connector_when_members_are_usable() {
        let mut ir = sb_config::ir::ConfigIR::default();
        ir.outbounds.push(direct_outbound("direct-a"));
        ir.outbounds.push(direct_outbound("direct-b"));
        ir.outbounds.push(selector_outbound(
            "manual",
            Some(vec!["direct-a", "direct-b"]),
        ));

        let mut map = HashMap::from([
            ("direct-a".to_string(), connector_impl("direct")),
            ("direct-b".to_string(), connector_impl("direct")),
        ]);
        bind_selector_outbound_groups(&ir, &mut map, None, history_service());

        assert!(matches!(
            map.get("manual"),
            Some(OutboundImpl::Connector(_))
        ));
    }

    #[test]
    fn urltest_binding_registers_connector_when_members_are_usable() {
        let mut ir = sb_config::ir::ConfigIR::default();
        ir.outbounds.push(direct_outbound("direct-a"));
        ir.outbounds
            .push(urltest_outbound("auto", Some(vec!["direct-a"])));

        let mut map = HashMap::from([("direct-a".to_string(), connector_impl("direct"))]);
        bind_selector_outbound_groups(&ir, &mut map, None, history_service());

        assert!(matches!(map.get("auto"), Some(OutboundImpl::Connector(_))));
    }

    #[test]
    fn collect_group_members_keeps_only_usable_connectors() {
        let existing = HashMap::from([
            ("direct-a".to_string(), connector_impl("direct")),
            ("socks-a".to_string(), connector_impl("socks")),
            ("http-a".to_string(), connector_impl("http")),
        ]);
        let members = vec![
            "direct-a".to_string(),
            "missing".to_string(),
            "socks-a".to_string(),
            "http-a".to_string(),
        ];

        let group_members = collect_group_members("manual", &members, &existing);
        let tags: Vec<_> = group_members.into_iter().map(|member| member.tag).collect();

        assert_eq!(
            tags,
            vec![
                "direct-a".to_string(),
                "socks-a".to_string(),
                "http-a".to_string()
            ]
        );
    }

    #[test]
    fn selector_binding_keeps_registered_connector_when_other_member_is_missing() {
        let mut ir = sb_config::ir::ConfigIR::default();
        ir.outbounds.push(direct_outbound("direct-a"));
        ir.outbounds
            .push(selector_outbound("manual", Some(vec!["missing", "http-a"])));

        let mut map = HashMap::from([("http-a".to_string(), connector_impl("http"))]);
        bind_selector_outbound_groups(&ir, &mut map, None, history_service());

        assert!(matches!(
            map.get("manual"),
            Some(OutboundImpl::Connector(_))
        ));
    }

    #[test]
    fn urltest_binding_skips_empty_members() {
        let mut ir = sb_config::ir::ConfigIR::default();
        ir.outbounds
            .push(urltest_outbound("auto", Some(Vec::new())));

        let mut map = HashMap::new();
        bind_selector_outbound_groups(&ir, &mut map, None, history_service());

        assert!(!map.contains_key("auto"));
    }

    #[test]
    fn selector_binding_skips_when_members_field_is_absent() {
        let mut ir = sb_config::ir::ConfigIR::default();
        ir.outbounds.push(selector_outbound("manual", None));

        let mut map = HashMap::new();
        bind_selector_outbound_groups(&ir, &mut map, None, history_service());

        assert!(!map.contains_key("manual"));
    }

    #[test]
    fn to_adapter_connector_is_pinned_for_bootstrap_second_pass() {
        assert!(to_adapter_connector(&connector_impl("direct")).is_some());
        assert!(to_adapter_connector(&connector_impl("block")).is_some());
        assert!(to_adapter_connector(&connector_impl("socks")).is_some());
        assert!(to_adapter_connector(&connector_impl("http")).is_some());
    }

    #[test]
    fn wp30al_pin_second_pass_owner_lives_in_outbound_groups_rs() {
        let source = include_str!("outbound_groups.rs");

        assert!(source.contains("pub(crate) fn bind_selector_outbound_groups"));
        assert!(source.contains("SelectorGroup::new_manual"));
        assert!(source.contains("SelectorGroup::new_urltest"));
        assert!(source.contains("fn to_adapter_connector("));
    }

    #[test]
    fn wp30al_pin_second_pass_owner_is_test_only_runtime_helper() {
        let lib = include_str!("lib.rs");

        assert!(lib.contains("#[cfg(all(feature = \"router\", test))]\nmod outbound_groups;"));
        assert!(
            !std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src/bootstrap.rs"))
                .exists()
        );
    }

    #[test]
    fn selector_connector_restores_default_selection() {
        let mut ir = sb_config::ir::ConfigIR::default();
        ir.outbounds.push(direct_outbound("direct-a"));
        ir.outbounds.push(direct_outbound("direct-b"));
        ir.outbounds.push(selector_outbound(
            "manual",
            Some(vec!["direct-a", "direct-b"]),
        ));

        let mut map = HashMap::from([
            ("direct-a".to_string(), connector_impl("direct")),
            ("direct-b".to_string(), connector_impl("direct")),
        ]);
        bind_selector_outbound_groups(&ir, &mut map, None, history_service());

        let OutboundImpl::Connector(connector) = map.get("manual").expect("selector registered")
        else {
            panic!("selector should be stored as connector");
        };
        let debug = format!("{connector:?}");

        assert!(debug.contains("SelectorGroup"));
        assert!(debug.contains("mode: Manual"));
        assert!(debug.contains("members_count: 2"));
    }

    #[test]
    fn urltest_connector_is_created_in_urltest_mode() {
        let mut ir = sb_config::ir::ConfigIR::default();
        ir.outbounds.push(direct_outbound("direct-a"));
        ir.outbounds
            .push(urltest_outbound("auto", Some(vec!["direct-a"])));

        let mut map = HashMap::from([("direct-a".to_string(), connector_impl("direct"))]);
        bind_selector_outbound_groups(&ir, &mut map, None, history_service());

        let OutboundImpl::Connector(connector) = map.get("auto").expect("urltest registered")
        else {
            panic!("urltest should be stored as connector");
        };
        let debug = format!("{connector:?}");

        assert!(debug.contains("SelectorGroup"));
        assert!(debug.contains("mode: UrlTest"));
        assert!(debug.contains("members_count: 1"));
    }
}
