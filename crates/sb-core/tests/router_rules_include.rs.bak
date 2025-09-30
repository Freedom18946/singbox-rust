use sb_core::router::{decide_http, router_build_index_from_str};
use sb_core::router::{router_index_from_env_with_reload, shared_index};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
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
        writeln!(f, "default=direct").unwrap();
    }

    std::env::set_var("SB_ROUTER_RULES_FILE", &main_path);
    std::env::set_var("SB_ROUTER_RULES_HOT_RELOAD_MS", "50");

    let shared = router_index_from_env_with_reload().await;
    // 给后台热载器一点时间
    tokio::time::sleep(std::time::Duration::from_millis(120)).await;

    // decide_http 使用共享索引
    let decision = decide_http("a.included");
    assert_eq!(decision.target, "proxy");

    // 修改 inc.rules，使其变为 direct
    fs::write(&inc_path, b"suffix:.included=direct\n").unwrap();
    // 等待热重载
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    let decision = decide_http("a.included");
    assert_eq!(decision.target, "direct");

    // 防止临时目录提前清理
    drop(shared);
    let _ = shared_index();
}
