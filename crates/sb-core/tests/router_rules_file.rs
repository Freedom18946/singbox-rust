#![cfg(feature = "router")]
use sb_core::router::router_index_with_reload;
use sb_core::runtime_options::RouterRuntimeOptions;
use std::fs;
use std::sync::Arc;
use std::time::Duration;
use tempfile::NamedTempFile;
use tokio::time::sleep;

#[tokio::test]
async fn hot_reload_success_and_failure_do_not_break() {
    let f = NamedTempFile::new().unwrap();
    fs::write(f.path(), b"suffix:example.com=proxy\ndefault=unresolved\n").unwrap();
    let shared = router_index_with_reload(Arc::new(RouterRuntimeOptions {
        rules_file: Some(f.path().to_path_buf()),
        rules_hot_reload_ms: 50,
        ..RouterRuntimeOptions::default()
    }))
    .await;
    {
        let idx = shared.read().unwrap().clone();
        assert_eq!(
            sb_core::router::router_index_decide_exact_suffix(&idx, "a.example.com").unwrap(),
            "proxy"
        );
    }
    // 写入新规则（切换）
    fs::write(f.path(), b"suffix:example.com=direct\ndefault=proxy\n").unwrap();
    sleep(Duration::from_millis(120)).await;
    {
        let idx = shared.read().unwrap().clone();
        assert_eq!(
            sb_core::router::router_index_decide_exact_suffix(&idx, "a.example.com").unwrap(),
            "direct"
        );
    }
    // 写入非法规则（应不切换）
    fs::write(f.path(), b"cidr4:10.0.0.0/99=direct\n").unwrap(); // invalid cidr
    sleep(Duration::from_millis(120)).await;
    {
        let idx = shared.read().unwrap().clone();
        // 仍然是上一版
        assert_eq!(
            sb_core::router::router_index_decide_exact_suffix(&idx, "a.example.com").unwrap(),
            "direct"
        );
    }
}
