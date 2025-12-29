// Integration test for Box Runtime Parity Context wiring
use sb_config::ir::{CacheFileIR, ConfigIR, ExperimentalIR, V2RayApiIR};
use sb_core::context::{Context, V2RayServer};
use std::sync::Arc;

#[tokio::test]
async fn test_context_service_wiring() {
    // Create ConfigIR with experimental services enabled
    let config = ConfigIR {
        experimental: Some(ExperimentalIR {
            cache_file: Some(CacheFileIR {
                enabled: true,
                path: Some("/tmp/test_cache.db".into()),
                store_fakeip: true,
                store_rdrc: false,
                rdrc_timeout: None,
            }),
            clash_api: None,
            v2ray_api: Some(V2RayApiIR {
                listen: Some("127.0.0.1:8080".into()),
                stats: None,
            }),
            debug: None,
        }),
        ..Default::default()
    };

    // Wire services from IR (simulating supervisor behavior)
    let mut context = Context::new();

    if let Some(exp) = &config.experimental {
        if let Some(cache_cfg) = &exp.cache_file {
            if cache_cfg.enabled {
                let cache_svc = Arc::new(sb_core::services::cache_file::CacheFileService::new(
                    cache_cfg,
                ));
                context = context.with_cache_file(cache_svc);
            }
        }

        if let Some(v2ray_cfg) = &exp.v2ray_api {
            let v2ray_server = Arc::new(sb_core::services::v2ray_api::V2RayApiServer::new(
                v2ray_cfg.clone(),
            ));
            let _ = v2ray_server.start();
            context = context.with_v2ray_server(v2ray_server);
        }
    }

    // Verify services are wired
    assert!(
        context.cache_file.is_some(),
        "Cache file service should be wired"
    );
    assert!(
        context.v2ray_server.is_some(),
        "V2Ray API server should be wired"
    );
}

#[tokio::test]
async fn test_context_registries() {
    let context = Context::new();

    // Test NetworkManager
    context
        .network
        .update_interface(
            "eth0".to_string(),
            vec!["192.168.1.1".parse().unwrap()],
            true,
        )
        .await;

    let interfaces = context.network.interfaces().await;
    assert_eq!(interfaces.len(), 1);
    assert_eq!(interfaces[0].name, "eth0");

    // Test ConnectionManager
    let conn_id = context.connections.register(
        "127.0.0.1:1234".into(),
        "example.com:443".into(),
        "tcp".into(),
    );
    assert_eq!(context.connections.count(), 1);

    let conn = context.connections.get(conn_id).unwrap();
    assert_eq!(conn.protocol, "tcp");

    context.connections.unregister(conn_id);
    assert_eq!(context.connections.count(), 0);

    // Test TaskMonitor
    let cancel_token = context.task_monitor.register("test_task".into());
    assert_eq!(context.task_monitor.count(), 1);
    assert!(!cancel_token.is_cancelled());

    context.task_monitor.cancel("test_task");
    assert!(cancel_token.is_cancelled());

    context.task_monitor.unregister("test_task");
    assert_eq!(context.task_monitor.count(), 0);

    // Test PlatformInterface
    let info = context.platform.info();
    assert!(!info.os.is_empty());
    assert!(!info.arch.is_empty());
}
