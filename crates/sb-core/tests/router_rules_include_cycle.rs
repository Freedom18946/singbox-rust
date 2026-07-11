#![cfg(feature = "router")]
use sb_core::router::router_build_index_from_str_with_options;
use sb_core::runtime_options::RouterRuntimeOptions;
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
        writeln!(fa, "default=unresolved").unwrap();
    }
    {
        let mut fb = fs::File::create(&b).unwrap();
        writeln!(fb, "include a.rules").unwrap(); // cycle
        writeln!(fb, "suffix:.cycle=reject").unwrap();
    }

    let options = RouterRuntimeOptions {
        rules_base_dir: Some(dir.path().to_path_buf()),
        rules_max_depth: 8,
        ..RouterRuntimeOptions::default()
    };
    let result = router_build_index_from_str_with_options("include a.rules", 1024, &options);
    assert!(result.is_err(), "include cycle must be rejected");
}
