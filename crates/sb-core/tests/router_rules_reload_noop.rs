use sb_core::router::router_index_with_reload;
use sb_core::runtime_options::RouterRuntimeOptions;
use std::fs;
use std::io::Write;
use std::sync::Arc;
use tempfile::tempdir;

#[tokio::test]
async fn hot_reload_noop_does_not_bump_generation() {
    let dir = tempdir().unwrap();
    let main_path = dir.path().join("rules.txt");
    {
        let mut f = fs::File::create(&main_path).unwrap();
        writeln!(f, "suffix:.noop=proxy").unwrap();
        writeln!(f, "default=unresolved").unwrap();
    }
    let shared = router_index_with_reload(Arc::new(RouterRuntimeOptions {
        rules_file: Some(main_path.clone()),
        rules_hot_reload_ms: 80,
        ..RouterRuntimeOptions::default()
    }))
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let gen1 = { shared.read().unwrap().gen };

    // 写入完全相同的内容（mtime 变化，内容不变）
    {
        let mut f = fs::File::create(&main_path).unwrap();
        writeln!(f, "suffix:.noop=proxy").unwrap();
        writeln!(f, "default=unresolved").unwrap();
    }
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let gen2 = { shared.read().unwrap().gen };
    assert_eq!(gen1, gen2, "noop reload should not bump generation");
}
