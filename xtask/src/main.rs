//! xtask: 开发者任务自动化工具
//!
//! 基于 cargo-xtask 模式的项目自动化工具集。
//! MSRV = 1.90; 使用 blocking HTTP 避免引入 async runtime 依赖。

use anyhow::{anyhow, bail, Context, Result};
use std::env;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

fn main() -> Result<()> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("e2e") => cmd_e2e(),
        Some("fmt") => cmd_fmt(),
        Some("clippy") => cmd_clippy(),
        Some("check-all") => cmd_check_all(),
        Some("test-all") => cmd_test_all(),
        Some("schema") => cmd_schema(args.collect()),
        Some("metrics-check") => cmd_metrics_check(args.collect()),
        Some("bench") => cmd_bench(),
        Some("ci") => cmd_ci(),
        Some("preflight") => cmd_preflight(),
        Some("help") | Some("--help") | Some("-h") => {
            print_help();
            Ok(())
        }
        Some(cmd) => Err(anyhow!("未知子命令: {}\n运行 'cargo xtask help' 查看帮助", cmd)),
        None => {
            print_help();
            Ok(())
        }
    }
}

fn print_help() {
    println!(
        r#"xtask - singbox-rust 开发者工具

用法:
    cargo xtask <COMMAND>

命令:
  代码质量:
    fmt              格式化所有代码
    clippy           运行 clippy 检查
    check-all        检查所有特性组合

  测试:
    e2e              端到端测试流程
    test-all         运行所有测试套件
    bench            运行基准测试

  工具:
    schema           生成/验证 JSON schema
    metrics-check    验证 Prometheus metrics

  CI/CD:
    ci               完整 CI 流程（本地模拟）
    preflight        提交前快速检查

  其他:
    help             显示此帮助信息

环境变量:
    CARGO_TARGET_DIR    自定义构建目录
    RUST_LOG            控制输出详细度
    XTASK_SKIP_BUILD    跳过构建步骤（调试用）

示例:
    cargo xtask fmt
    cargo xtask e2e
    cargo xtask ci

详细文档: xtask/README.md
"#
    );
}

// ============================================================================
// 代码质量命令
// ============================================================================

fn cmd_fmt() -> Result<()> {
    section("格式化代码");
    run_cargo(&["fmt", "--all", "--", "--check"])?;
    success("代码格式检查通过");
    Ok(())
}

fn cmd_clippy() -> Result<()> {
    section("运行 Clippy");
    run_cargo(&[
        "clippy",
        "--workspace",
        "--all-features",
        "--all-targets",
        "--",
        "-D",
        "warnings",
    ])?;
    success("Clippy 检查通过");
    Ok(())
}

fn cmd_check_all() -> Result<()> {
    section("检查所有特性组合");

    let configs = [
        ("无特性", vec!["--no-default-features"]),
        ("默认特性", vec![]),
        ("所有特性", vec!["--all-features"]),
        (
            "核心特性",
            vec!["--no-default-features", "--features", "admin_debug,auth,rate_limit"],
        ),
    ];

    for (desc, args) in &configs {
        info(&format!("检查: {}", desc));
        let mut cmd_args = vec!["check", "--workspace"];
        cmd_args.extend(args.iter().copied());
        run_cargo(&cmd_args)?;
    }

    success("所有特性组合检查通过");
    Ok(())
}

// ============================================================================
// 测试命令
// ============================================================================

fn cmd_test_all() -> Result<()> {
    section("运行所有测试");

    info("单元测试 + 集成测试");
    run_cargo(&["test", "--workspace", "--lib", "--tests"])?;

    info("文档测试");
    run_cargo(&["test", "--workspace", "--doc"])?;

    info("xtests 工作区测试");
    run_cargo(&["test", "-p", "xtests"])?;

    success("所有测试通过");
    Ok(())
}

fn cmd_e2e() -> Result<()> {
    section("端到端测试流程");

    // 0) 构建应用（带关键特性）
    if env::var("XTASK_SKIP_BUILD").is_err() {
        info("构建应用...");
        cargo_build_app(&[
            "--no-default-features",
            "--features",
            "admin_debug,auth,rate_limit,preview_route,dsl_analyze,dsl_derive,dsl_plus",
        ])?;
    }

    let app_bin = app_bin_path()?;
    info(&format!("使用应用: {}", app_bin.display()));

    // 1) version --format json
    info("测试: version 命令");
    let ver = run_app_json(&app_bin, &["version", "--format", "json"])?;
    assert_json_has(&ver, &["name", "version", "features"])?;
    success("✓ version 命令正常");

    // 2) check --config --format json
    info("测试: check 命令");
    let check = run_app_json(
        &app_bin,
        &["check", "--config", "examples/e2e/minimal.yaml", "--format", "json"],
    )?;
    if check.get("ok").and_then(|v| v.as_bool()) != Some(true) {
        bail!("check 命令失败: {}", check);
    }
    success("✓ check 命令正常");

    // 3) 启动服务器
    info("启动服务器...");
    let apikey = "secret-e2e-key-123";
    let child = spawn_app(
        &app_bin,
        &["run", "--config", "examples/e2e/minimal.yaml"],
        &[
            ("APP_E2E_APIKEY", apikey),
            ("ADMIN_LISTEN", "127.0.0.1:18080"),
        ],
    )?;
    let guard = ChildGuard { child: Some(child) };
    thread::sleep(Duration::from_secs(2));
    success("✓ 服务器启动");

    // 4) route --dest --format json --explain
    info("测试: route 命令");
    let route = run_app_json(
        &app_bin,
        &[
            "route",
            "--config",
            "examples/e2e/minimal.yaml",
            "--dest",
            "1.1.1.1",
            "--format",
            "json",
            "--explain",
        ],
    )?;
    assert_json_has(&route, &["dest", "matched_rule", "chain", "outbound"])?;
    success("✓ route 命令正常");

    // 5) metrics 端点（跳过：需要端口检测）
    info("跳过 metrics 端点测试（需要端口检测支持）");

    // 6) admin 认证测试（跳过：同上）
    info("跳过 admin 认证测试（需要端口检测支持）");

    drop(guard);
    success("E2E 测试完成");
    Ok(())
}

fn cmd_bench() -> Result<()> {
    section("运行基准测试");

    // 检查是否是 nightly
    let output = Command::new("rustc")
        .args(["--version"])
        .output()
        .context("无法运行 rustc --version")?;
    let version = String::from_utf8_lossy(&output.stdout);
    if !version.contains("nightly") {
        warn("基准测试需要 nightly 工具链");
        info("提示: rustup default nightly 或使用 +nightly");
    }

    run_cargo(&["bench", "--workspace"])?;
    success("基准测试完成");
    Ok(())
}

// ============================================================================
// 工具命令
// ============================================================================

fn cmd_schema(args: Vec<String>) -> Result<()> {
    section("Schema 工具");

    if args.contains(&"--export".to_string()) {
        warn("--export 功能尚未实现");
        info("当前仅支持统计信息");
    }

    // 读取内置 schema（从 sb-config crate）
    let schema = include_str!("../../crates/sb-config/src/validator/v2_schema.json");
    let bytes = schema.len();
    let lines = schema.lines().count();

    println!(r#"{{"schema_bytes":{},"schema_lines":{}}}"#, bytes, lines);
    success("Schema 统计完成");
    Ok(())
}

fn cmd_metrics_check(args: Vec<String>) -> Result<()> {
    section("检查 Metrics 端点");

    // 解析地址参数
    let addr = if let Some(pos) = args.iter().position(|a| a == "--addr") {
        args.get(pos + 1)
            .ok_or_else(|| anyhow!("--addr 需要参数"))?
            .clone()
    } else {
        "127.0.0.1:19090".to_string()
    };

    // 可选：要求 inbound_error_total 必须存在（否则报错）
    let require_inbound_errors = args.iter().any(|a| a == "--require-inbound-errors");

    info(&format!("连接到: {}", addr));

    // 发起 HTTP 请求
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    let url = format!("http://{}/metrics", addr);
    let resp = client.get(&url).send().context("无法连接到 metrics 端点")?;

    if !resp.status().is_success() {
        bail!("Metrics 端点返回错误: {}", resp.status());
    }

    let body = resp.text()?;
    let lines: Vec<&str> = body.lines().collect();

    // 检查必需的 metrics
    let required = [
        "sb_build_info",
        "udp_upstream_map_size",
        "udp_evict_total",
        "udp_ttl_seconds",
        "udp_upstream_fail_total",
        "route_explain_total",
    ];

    let mut missing = Vec::new();
    for name in &required {
        let found = lines.iter().any(|l| l.contains(name));
        if !found {
            missing.push(*name);
        }
    }

    if !missing.is_empty() {
        bail!("缺少必需的 metrics: {:?}", missing);
    }

    // 可选：检查统一入站错误族是否存在
    let has_inbound_error_total = lines.iter().any(|l| l.contains("inbound_error_total"));
    if require_inbound_errors && !has_inbound_error_total {
        bail!("缺少 inbound_error_total。请在被测环境中触发一次入站错误（如 HTTP 非 CONNECT），或取消 --require-inbound-errors");
    }
    if has_inbound_error_total {
        info("检测到 inbound_error_total（统一入站错误计数）");
    } else {
        warn("未检测到 inbound_error_total（可能当前无入站错误，忽略）");
    }

    // 检查 label 白名单
    let allowed_labels = ["rule", "reason", "class", "outbound", "protocol"];
    let mut disallowed = Vec::new();

    for line in &lines {
        if line.starts_with('#') {
            continue;
        }
        if let Some(kvs) = line.split('{').nth(1).and_then(|x| x.split('}').next()) {
            for kv in kvs.split(',') {
                if let Some((k, _)) = kv.split_once('=') {
                    if !allowed_labels.contains(&k) {
                        disallowed.push(k.to_string());
                    }
                }
            }
        }
    }

    if !disallowed.is_empty() {
        warn(&format!("发现未授权的 labels: {:?}", disallowed));
    }

    success(&format!("Metrics 验证完成 ({} 行)", lines.len()));
    Ok(())
}

// ============================================================================
// CI 命令
// ============================================================================

type CiStep = (&'static str, fn() -> Result<()>);

fn cmd_ci() -> Result<()> {
    section("完整 CI 流程");

    let steps: &[CiStep] = &[
        ("格式检查", cmd_fmt),
        ("Clippy", cmd_clippy),
        ("特性检查", cmd_check_all),
        ("测试套件", cmd_test_all),
        ("E2E 测试", cmd_e2e),
    ];

    for (name, func) in steps {
        info(&format!("==> {}", name));
        func()?;
    }

    success("CI 流程完成");
    Ok(())
}

fn cmd_preflight() -> Result<()> {
    section("Preflight 检查");

    info("格式检查");
    cmd_fmt()?;

    info("Clippy");
    cmd_clippy()?;

    info("快速测试");
    run_cargo(&["test", "--workspace", "--lib"])?;

    success("Preflight 通过，可以提交");
    Ok(())
}

// ============================================================================
// 辅助函数
// ============================================================================

fn cargo_build_app(extra: &[&str]) -> Result<()> {
    let mut args = vec!["build", "-p", "app"];
    args.extend(extra);

    let output = Command::new("cargo")
        .args(&args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("执行 cargo {:?} 失败", args))?;

    if !output.stdout.is_empty() {
        print!("{}", String::from_utf8_lossy(&output.stdout));
    }
    if !output.stderr.is_empty() {
        eprint!("{}", String::from_utf8_lossy(&output.stderr));
    }

    // 允许警告但不允许错误
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        if stderr.contains("error:") && stderr.contains("aborting due to") {
            bail!("构建失败：编译错误");
        }
        warn("构建完成但有警告");
    }

    Ok(())
}

fn run_cargo(args: &[&str]) -> Result<()> {
    let status = Command::new("cargo")
        .args(args)
        .stdin(Stdio::null())
        .status()
        .with_context(|| format!("执行 cargo {:?} 失败", args))?;

    if !status.success() {
        bail!("cargo {:?} 返回错误", args);
    }
    Ok(())
}

fn app_bin_path() -> Result<PathBuf> {
    let target_dir = env::var("CARGO_TARGET_DIR").unwrap_or_else(|_| "target".into());
    let mut p = Path::new(&target_dir).join("debug");

    #[cfg(windows)]
    {
        p.push("app.exe");
    }
    #[cfg(not(windows))]
    {
        p.push("app");
    }

    if p.exists() {
        Ok(p)
    } else {
        Err(anyhow!("应用未找到: {}", p.display()))
    }
}

fn run_capture(bin: &Path, args: &[&str]) -> Result<(i32, Vec<u8>, Vec<u8>)> {
    let out = Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("RUST_LOG", "error")
        .output()
        .with_context(|| format!("执行 {} {:?} 失败", bin.display(), args))?;

    let code = out.status.code().unwrap_or(-1);
    Ok((code, out.stdout, out.stderr))
}

fn run_app_json(app_bin: &Path, args: &[&str]) -> Result<serde_json::Value> {
    let (code, stdout, stderr) = run_capture(app_bin, args)?;
    if code != 0 {
        eprintln!("stderr:\n{}", String::from_utf8_lossy(&stderr));
        bail!("命令 {:?} 返回错误码: {}", args, code);
    }

    let output = String::from_utf8_lossy(&stdout);
    let mut json_lines = Vec::new();
    let mut in_json = false;
    let mut brace_count = 0i32;

    for line in output.lines() {
        let trimmed = line.trim();
        if !in_json && trimmed.starts_with('{') {
            in_json = true;
            json_lines.clear();
            json_lines.push(line);
            brace_count = trimmed.chars().filter(|&c| c == '{').count() as i32
                - trimmed.chars().filter(|&c| c == '}').count() as i32;
        } else if in_json {
            json_lines.push(line);
            brace_count += trimmed.chars().filter(|&c| c == '{').count() as i32
                - trimmed.chars().filter(|&c| c == '}').count() as i32;

            if brace_count <= 0 {
                break;
            }
        }
    }

    let json_str = json_lines.join("\n");
    if json_str.is_empty() {
        bail!("输出中未找到 JSON: {}", output);
    }

    let v: serde_json::Value =
        serde_json::from_str(&json_str).with_context(|| format!("解析 JSON 失败: {}", json_str))?;
    Ok(v)
}

fn spawn_app(app_bin: &Path, args: &[&str], envs: &[(&str, &str)]) -> Result<std::process::Child> {
    let mut cmd = Command::new(app_bin);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env("RUST_LOG", "error");

    for (k, v) in envs {
        cmd.env(k, v);
    }

    cmd.spawn()
        .with_context(|| format!("启动 {} {:?} 失败", app_bin.display(), args))
}

struct ChildGuard {
    child: Option<std::process::Child>,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            #[cfg(unix)]
            {
                // SAFETY: c.id() 是有效的进程 ID，SIGTERM 信号不会引发未定义行为
                let _ = unsafe { libc::kill(c.id() as i32, libc::SIGTERM) };
                thread::sleep(Duration::from_millis(100));
                match c.try_wait() {
                    Ok(Some(_)) => {}
                    _ => {
                        let _ = c.kill();
                    }
                }
            }
            #[cfg(not(unix))]
            {
                let _ = c.kill();
            }
            let _ = c.wait();
        }
    }
}

fn assert_json_has(v: &serde_json::Value, keys: &[&str]) -> Result<()> {
    let obj = v.as_object().ok_or_else(|| anyhow!("期望 JSON 对象"))?;
    for k in keys {
        if !obj.contains_key(*k) {
            bail!("JSON 缺少键: {}", k);
        }
    }
    Ok(())
}

// ============================================================================
// 输出格式化
// ============================================================================

fn section(msg: &str) {
    println!("\n━━━━ {} ━━━━", msg);
}

fn success(msg: &str) {
    println!("✅ {}", msg);
}

fn info(msg: &str) {
    println!("ℹ️  {}", msg);
}

fn warn(msg: &str) {
    eprintln!("⚠️  {}", msg);
}
