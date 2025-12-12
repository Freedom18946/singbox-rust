fn main() {
    use std::process::Command;
    fn cmd_out(args: &[&str]) -> String {
        Command::new(args[0])
            .args(&args[1..])
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .unwrap_or_default()
            .trim()
            .to_string()
    }
    let git = std::env::var("SB_GIT_SHA")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            cmd_out(&[
                "bash",
                "-lc",
                "git rev-parse --short=12 HEAD 2>/dev/null || echo unknown",
            ])
        });
    let rustc = cmd_out(&["rustc", "--version"]);
    let profile = std::env::var("PROFILE").unwrap_or_default();
    let features = std::env::var("CARGO_FEATURES").unwrap_or_default();
    println!("cargo:rustc-env=SB_GIT_SHA={}", git);
    println!("cargo:rustc-env=SB_RUSTC={}", rustc);
    println!("cargo:rustc-env=SB_PROFILE={}", profile);
    println!("cargo:rustc-env=SB_FEATURES={}", features);
    // 可复现：允许外部注入 SOURCE_DATE_EPOCH；否则用构建时刻（非严格）
    let ts = std::env::var("SOURCE_DATE_EPOCH").ok().unwrap_or_else(|| {
        // 低依赖写法，避免引 chrono 进 build-deps
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .to_string()
    });
    println!("cargo:rustc-env=SB_BUILD_TIME_EPOCH={}", ts);

    // Add BUILD_TS and GIT_SHA for report functionality
    let ts_rfc3339 = chrono::Utc::now().to_rfc3339();
    println!("cargo:rustc-env=BUILD_TS={}", ts_rfc3339);
    println!("cargo:rustc-env=GIT_SHA={}", git);
    let target = std::env::var("TARGET").unwrap_or_default();
    println!("cargo:rustc-env=TARGET={}", target);
}
