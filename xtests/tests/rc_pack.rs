use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

fn project_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn find_run_rc_script(root: &Path) -> PathBuf {
    let path = root.join("app/scripts/run-rc");
    if path.exists() {
        return path;
    }
    panic!("run-rc script not found in expected locations");
}

fn normalize_rc_dir(root: &Path, stdout: &str) -> Option<PathBuf> {
    let last_line = stdout.lines().rev().find(|line| !line.trim().is_empty())?;
    let out = PathBuf::from(last_line.trim());
    if out.is_absolute() {
        Some(out)
    } else {
        Some(root.join(out))
    }
}

fn has_fresh_artifact(rc_dir: &Path, prefix: &str, started: SystemTime) -> bool {
    fs::read_dir(rc_dir)
        .ok()
        .into_iter()
        .flat_map(|iter| iter.filter_map(Result::ok))
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(prefix))
        .any(|entry| {
            entry
                .metadata()
                .and_then(|metadata| metadata.modified())
                .map(|modified| modified >= started)
                .unwrap_or(false)
        })
}

#[test]
fn rc_pack_generates_snapshots() {
    let root = project_root();
    let run_rc = find_run_rc_script(&root);
    let started = SystemTime::now();

    let output = Command::new("bash")
        .arg(run_rc)
        .current_dir(&root)
        .output()
        .expect("scripts/run-rc");

    assert!(
        output.status.success(),
        "run-rc failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let rc_dir = normalize_rc_dir(&root, &stdout).expect("run-rc did not print output path");
    assert!(
        rc_dir.exists(),
        "rc directory missing: {}",
        rc_dir.display()
    );

    let has_version = has_fresh_artifact(&rc_dir, "version-", started);
    let has_ci_metadata = has_fresh_artifact(&rc_dir, "ci-metadata-", started);
    let has_manifest = has_fresh_artifact(&rc_dir, "manifest-", started);

    assert!(
        has_version && has_ci_metadata && has_manifest,
        "missing required rc artifacts in {}",
        rc_dir.display()
    );
}
