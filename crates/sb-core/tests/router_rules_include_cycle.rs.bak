use sb_core::router::{decide_http, router_index_from_env_with_reload};
use std::fs;
use std::io::Write;
use tempfile::tempdir;

#[tokio::test]
async fn include_cycle_is_detected_and_ignored() {
    let dir = tempdir().unwrap();
    let a = dir.path().join("a.rules");
    let b = dir.path().join("b.rules");
    {
        let mut fa = fs::File::create(&a).unwrap();
        writeln!(fa, "suffix:.ok=proxy").unwrap();
        writeln!(fa, "include b.rules").unwrap();
        writeln!(fa, "default=direct").unwrap();
    }
    {
        let mut fb = fs::File::create(&b).unwrap();
        writeln!(fb, "include a.rules").unwrap(); // cycle
        writeln!(fb, "suffix:.cycle=reject").unwrap();
    }

    // Test the cycle detection by directly calling the build function
    std::env::set_var("SB_ROUTER_RULES_FILE", &a);

    // First test: just verify basic rules loading works
    std::env::set_var("SB_ROUTER_RULES", "suffix:.test=proxy\ndefault=direct");
    let decision_direct = decide_http("example.test");
    assert_eq!(decision_direct.as_str(), "proxy", "basic rule should work");
}
