use sb_config::ir::{CacheFileIR, StatsIR, V2RayApiIR};
use sb_core::adapter::surface::AdapterServices;
use sb_core::context::{Context, ContextRegistry};
use sb_core::dns::dns_router::NullDnsRouter;
use sb_core::services::cache_file::CacheFileService;
use sb_core::services::urltest_history::URLTestHistoryService;
use sb_core::services::v2ray_api::V2RayApiServer;
use sb_types::ports::{
    AdapterServicePorts, CacheFilePort, ClashServerPort, RouteMetadata, UrlTestHistory,
    UrlTestHistoryPort, V2RayServerPort,
};
use sb_types::InboundTag;
use std::sync::Arc;
use std::time::SystemTime;

struct AdapterContracts {
    cache: Arc<dyn CacheFilePort>,
    history: Arc<dyn UrlTestHistoryPort>,
    clash: Arc<dyn ClashServerPort>,
    v2ray: Arc<dyn V2RayServerPort>,
}

fn consume_contracts(ports: &AdapterServicePorts) -> AdapterContracts {
    AdapterContracts {
        cache: ports.cache_file.clone().expect("cache contract"),
        history: ports.urltest_history.clone().expect("urltest contract"),
        clash: ports.clash_server.clone().expect("clash contract"),
        v2ray: ports.v2ray_server.clone().expect("v2ray contract"),
    }
}

#[test]
fn adapter_services_expose_trait_object_contracts_without_downcast() {
    let cache = Arc::new(CacheFileService::memory(&CacheFileIR {
        enabled: true,
        path: None,
        cache_id: None,
        store_fakeip: true,
        store_rdrc: true,
        rdrc_timeout: Some("1h".into()),
    }));
    let history = Arc::new(URLTestHistoryService::new());
    let v2ray_impl = Arc::new(V2RayApiServer::new(V2RayApiIR {
        listen: None,
        stats: Some(StatsIR {
            enabled: true,
            inbound: Some(true),
            outbound: Some(true),
            ..Default::default()
        }),
    }));
    v2ray_impl
        .stats()
        .get_counter("inbound>>>mixed-in>>>traffic>>>uplink")
        .add(17);

    let context = Context::new()
        .with_cache_file(cache)
        .with_urltest_history(history)
        .with_v2ray_server(v2ray_impl.clone());
    let registry = ContextRegistry::from(&context);
    let services = AdapterServices::from_context_registry_with_dns_router(
        &registry,
        Some(Arc::new(NullDnsRouter)),
    );
    let AdapterContracts {
        cache,
        history,
        clash,
        v2ray,
    } = consume_contracts(services.ports());

    cache.store_mode("rule").expect("mode store");
    assert_eq!(cache.load_mode().as_deref(), Some("rule"));

    cache
        .store_selected("selector", "proxy-a")
        .expect("selection store");
    assert_eq!(cache.load_selected("selector").as_deref(), Some("proxy-a"));

    cache
        .store_group_expand("selector", true)
        .expect("expand store");
    assert_eq!(cache.load_group_expand("selector"), Some(true));

    let fake_ip = "198.18.0.10".parse().unwrap();
    cache.save_mapping("example.com", fake_ip);
    assert_eq!(cache.load_domain("example.com", false), Some(fake_ip));
    assert_eq!(cache.load_address(fake_ip).as_deref(), Some("example.com"));

    assert!(!cache.load_rdrc("dns-local", "blocked.example", 1));
    cache
        .save_rdrc("dns-local", "blocked.example", 1)
        .expect("rdrc store");
    assert!(cache.load_rdrc("dns-local", "blocked.example", 1));

    cache
        .save_rule_set(
            "geoip",
            sb_types::ports::SavedRuleSetBinary {
                content: vec![1, 2, 3],
                last_updated: SystemTime::UNIX_EPOCH,
                last_etag: "etag".into(),
            },
        )
        .expect("ruleset store");
    assert_eq!(
        cache.load_rule_set("geoip").map(|set| set.content),
        Some(vec![1, 2, 3])
    );

    history.store_history(
        "proxy-a",
        UrlTestHistory {
            time: SystemTime::UNIX_EPOCH,
            delay: 42,
        },
    );
    assert_eq!(history.load_history("proxy-a").map(|h| h.delay), Some(42));

    clash.set_mode("direct").expect("clash mode update");
    assert_eq!(clash.mode(), "direct");
    clash.set_mode("rule").expect("clash mode reset");

    let stats = v2ray.stats_service().expect("v2ray stats contract");
    assert_eq!(
        stats.query("traffic", false),
        vec![("inbound>>>mixed-in>>>traffic>>>uplink".into(), 17)]
    );
    stats.routed_stream(
        &RouteMetadata {
            inbound: Some(InboundTag::new("mixed-in")),
            ..Default::default()
        },
        None,
        Some("direct"),
    );
    assert_eq!(
        v2ray_impl
            .stats()
            .get_stat("outbound>>>direct>>>traffic>>>downlink"),
        Some(0)
    );
    assert!(v2ray_impl
        .stats()
        .get_stat("inbound>>>mixed-in>>>packet>>>uplink")
        .is_none());
    stats.routed_packet(
        &RouteMetadata {
            inbound: Some(InboundTag::new("dns-in")),
            ..Default::default()
        },
        None,
        Some("dns-out"),
    );
    assert_eq!(
        v2ray_impl
            .stats()
            .get_stat("inbound>>>dns-in>>>traffic>>>uplink"),
        Some(0)
    );
    assert_eq!(
        v2ray_impl
            .stats()
            .get_stat("outbound>>>dns-out>>>traffic>>>downlink"),
        Some(0)
    );

    assert!(services.ports().time_service.is_some());
    assert!(services.ports().certificate_store.is_some());
    assert!(services.ports().dns_router.is_some());
}
