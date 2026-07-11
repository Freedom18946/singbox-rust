#![cfg(feature = "router")]
use sb_core::router::{router_index_decide_exact_suffix, router_index_with_reload};
use sb_core::runtime_options::RouterRuntimeOptions;
use std::fs;
use std::io::Write;
use std::sync::Arc;
use tempfile::tempdir;

#[tokio::test]
async fn include_is_expanded_in_hot_reload() {
    let dir = tempdir().unwrap();
    let base = dir.path().to_path_buf();
    // 写入被包含文件
    let inc_path = base.join("inc.rules");
    fs::write(&inc_path, b"suffix:.included=proxy\n").unwrap();
    // 写入主文件，包含 inc.rules
    let main_path = base.join("main.rules");
    {
        let mut f = fs::File::create(&main_path).unwrap();
        writeln!(f, "include inc.rules").unwrap();
        writeln!(f, "default=unresolved").unwrap();
    }

    let shared = router_index_with_reload(Arc::new(RouterRuntimeOptions {
        rules_file: Some(main_path.clone()),
        rules_base_dir: Some(base),
        rules_hot_reload_ms: 50,
        ..RouterRuntimeOptions::default()
    }))
    .await;
    // 给后台热载器一点时间
    tokio::time::sleep(std::time::Duration::from_millis(120)).await;

    let idx = shared.read().unwrap().clone();
    assert_eq!(
        router_index_decide_exact_suffix(&idx, "a.included").unwrap(),
        "proxy"
    );

    // 修改 inc.rules，使其变为 direct
    fs::write(&inc_path, b"suffix:.included=direct\n").unwrap();
    // 等待热重载
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let idx = shared.read().unwrap().clone();
    assert_eq!(
        router_index_decide_exact_suffix(&idx, "a.included").unwrap(),
        "direct"
    );

    drop(shared);
}
