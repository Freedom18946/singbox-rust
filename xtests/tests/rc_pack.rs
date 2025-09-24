use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn project_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

#[test]
fn rc_pack_generates_snapshots() {
    let root = project_root();
    let rc_dir = root.join("target/rc");
    let _ = fs::remove_dir_all(&rc_dir);

    let status = Command::new("bash")
        .arg("scripts/run-rc")
        .current_dir(&root)
        .status()
        .expect("scripts/run-rc");
    assert!(status.success(), "run-rc failed");

    assert!(rc_dir.exists(), "rc directory missing");
    let manifest_json = rc_dir.join("rc_manifest.json");
    let manifest_files = rc_dir.join("manifest.files");
    assert!(
        manifest_json.exists() || manifest_files.exists(),
        "no manifest generated"
    );

    let snapshots_dir = rc_dir.join("snapshots");
    assert!(snapshots_dir.exists(), "snapshots directory missing");
    let mut entries = fs::read_dir(&snapshots_dir)
        .map(|iter| iter.filter_map(Result::ok).count())
        .unwrap_or_default();
    assert!(entries > 0, "snapshots directory is empty");
}
