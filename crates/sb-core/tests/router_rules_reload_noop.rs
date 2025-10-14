use sb_core::router::{router_index_from_env_with_reload, shared_index};
use std::fs;
use std::io::Write;
use tempfile::tempdir;

#[tokio::test]
async fn hot_reload_noop_does_not_bump_generation() {
    let dir = tempdir().unwrap();
    let main_path = dir.path().join("rules.txt");
    {
        let mut f = fs::File::create(&main_path).unwrap();
        writeln!(f, "suffix:.noop=proxy").unwrap();
        writeln!(f, "default=direct").unwrap();
    }
    std::env::set_var("SB_ROUTER_RULES_FILE", &main_path);
    std::env::set_var("SB_ROUTER_RULES_HOT_RELOAD_MS", "80");
    let _h = router_index_from_env_with_reload().await;
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let gen1 = { shared_index().read().unwrap().gen };

    // 写入完全相同的内容（mtime 变化，内容不变）
    {
        let mut f = fs::File::create(&main_path).unwrap();
        writeln!(f, "suffix:.noop=proxy").unwrap();
        writeln!(f, "default=direct").unwrap();
    }
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    let gen2 = { shared_index().read().unwrap().gen };
    assert_eq!(gen1, gen2, "noop reload should not bump generation");
}
