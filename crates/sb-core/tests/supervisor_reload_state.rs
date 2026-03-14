use sb_config::ir::{
    CacheFileIR, ConfigIR, ExperimentalIR, OutboundIR, OutboundType, RouteIR, RuleIR,
};
use sb_core::adapter::registry::RegistrySnapshot;
use sb_core::runtime::supervisor::Supervisor;

#[tokio::test]
async fn selector_selection_survives_reload_via_cache_file() {
    std::env::set_var("SB_INBOUND_RELOAD_GRACE_MS", "0");

    let temp_dir = tempfile::tempdir().expect("temp dir");
    let cache_dir = temp_dir.path().join("selector-cache");

    let initial_ir = ConfigIR {
        experimental: Some(ExperimentalIR {
            cache_file: Some(CacheFileIR {
                enabled: true,
                path: Some(cache_dir.to_string_lossy().into_owned()),
                cache_id: Some("reload-state".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        }),
        outbounds: vec![
            OutboundIR {
                ty: OutboundType::Selector,
                name: Some("S".to_string()),
                members: Some(vec!["A".to_string(), "B".to_string()]),
                default_member: Some("A".to_string()),
                ..Default::default()
            },
            OutboundIR {
                ty: OutboundType::Direct,
                name: Some("A".to_string()),
                ..Default::default()
            },
            OutboundIR {
                ty: OutboundType::Direct,
                name: Some("B".to_string()),
                ..Default::default()
            },
        ],
        route: RouteIR {
            rules: vec![RuleIR {
                domain: vec!["*".to_string()],
                outbound: Some("S".to_string()),
                ..Default::default()
            }],
            default: Some("A".to_string()),
            ..Default::default()
        },
        ..Default::default()
    };

    let registry: RegistrySnapshot = sb_adapters::build_default_registry();
    let supervisor = Supervisor::start_with_registry(initial_ir.clone(), Some(registry))
        .await
        .expect("start supervisor");
    let handle = supervisor.handle();

    {
        let state = handle.state().await;
        let guard = state.read().await;
        let connector = guard
            .bridge
            .find_outbound("S")
            .expect("selector outbound present");
        let group = connector.as_group().expect("selector group");
        assert_eq!(group.now(), "A");

        group.select_outbound("B").await.expect("select B");

        let cache = guard
            .context
            .cache_file
            .as_ref()
            .expect("cache file service wired");
        assert_eq!(cache.get_selected("S").as_deref(), Some("B"));
    }

    supervisor
        .reload(initial_ir.clone())
        .await
        .expect("reload supervisor");

    {
        let state = handle.state().await;
        let guard = state.read().await;
        let connector = guard
            .bridge
            .find_outbound("S")
            .expect("selector outbound present after reload");
        let group = connector.as_group().expect("selector group after reload");
        assert_eq!(
            group.now(),
            "B",
            "reload should restore selected outbound from cache file"
        );
    }

    supervisor
        .shutdown_graceful(std::time::Duration::from_secs(1))
        .await
        .expect("shutdown supervisor");
}
