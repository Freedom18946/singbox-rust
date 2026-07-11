#![allow(clippy::await_holding_lock)]

use sb_config::ir::{
    CacheFileIR, ConfigIR, ExperimentalIR, OutboundIR, OutboundType, RouteIR, RuleIR,
};
use sb_core::adapter::registry::RegistrySnapshot;
use sb_core::runtime::supervisor::Supervisor;
use std::sync::{Mutex, MutexGuard, OnceLock};

fn clash_state_guard() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|e| e.into_inner())
}

#[tokio::test]
async fn selector_selection_survives_reload_via_cache_file() {
    let _guard = clash_state_guard();
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
        assert_eq!(group.now().as_str(), "A");

        group
            .as_selector_control()
            .expect("selector control")
            .select("B")
            .await
            .expect("select B");

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
            group.now().as_str(),
            "B",
            "reload should restore selected outbound from cache file"
        );
    }

    supervisor
        .shutdown_graceful(std::time::Duration::from_secs(1))
        .await
        .expect("shutdown supervisor");
    sb_core::adapter::clash::set_mode(sb_core::adapter::clash::ClashMode::Rule);
}

#[tokio::test]
async fn clash_mode_restores_from_cache_file_on_start() {
    let _guard = clash_state_guard();
    let temp_dir = tempfile::tempdir().expect("temp dir");
    let cache_dir = temp_dir.path().join("clash-mode-cache");
    let cache_cfg = CacheFileIR {
        enabled: true,
        path: Some(cache_dir.to_string_lossy().into_owned()),
        cache_id: Some("clash-mode".to_string()),
        ..Default::default()
    };

    {
        let cache = sb_core::services::cache_file::CacheFileService::new(&cache_cfg);
        cache.set_clash_mode("global".to_string());
        cache.flush();
    }
    sb_core::adapter::clash::set_mode(sb_core::adapter::clash::ClashMode::Rule);

    let ir = ConfigIR {
        experimental: Some(ExperimentalIR {
            cache_file: Some(cache_cfg),
            ..Default::default()
        }),
        outbounds: vec![OutboundIR {
            ty: OutboundType::Direct,
            name: Some("direct".to_string()),
            ..Default::default()
        }],
        route: RouteIR {
            default: Some("direct".to_string()),
            ..Default::default()
        },
        ..Default::default()
    };

    let registry: RegistrySnapshot = sb_adapters::build_default_registry();
    let supervisor = Supervisor::start_with_registry(ir, Some(registry))
        .await
        .expect("start supervisor");

    assert_eq!(
        sb_core::adapter::clash::get_mode(),
        sb_core::adapter::clash::ClashMode::Global
    );

    supervisor
        .shutdown_graceful(std::time::Duration::from_secs(1))
        .await
        .expect("shutdown supervisor");
}
