use clap::Parser;
use sb_config::validator::v2::to_ir_v1;
use sb_core::adapter::bridge::build_bridge;
use sb_core::routing::engine::Engine;
use serde_json::json;
use std::fs;

#[derive(Parser, Debug)]
#[command(name = "preflight")]
#[command(about = "Validate config → IR → Bridge; print a fixed JSON contract")]
struct Args {
    #[arg(short = 'c', long = "config")]
    config: String,
}

fn main() {
    let args = Args::parse();
    let raw = fs::read(&args.config).unwrap_or_else(|_| b"{}".to_vec());
    let val: serde_json::Value = serde_json::from_slice(&raw).unwrap_or(serde_json::json!({}));
    let ir = to_ir_v1(&val);
    let eng = Engine::new(&ir);
    let br = build_bridge(&ir, eng, sb_core::context::Context::default());
    let inbound_cnt = br.inbounds.len();
    let outbounds = br.outbounds_snapshot();
    // 选择器成员存在性简报（best-effort）
    let mut selector_ok = true;
    for (n, k) in &outbounds {
        if k == "selector" {
            selector_ok = selector_ok && br.find_outbound(n).is_some();
        }
    }
    // Admin 安全态（仅基于参数/ENV 推断，可选字段）
    let admin_enabled = std::env::var("ADMIN_LISTEN").ok().is_some();
    let token_present = std::env::var("ADMIN_TOKEN").ok().is_some();
    let obj = json!({
        "event":"preflight",
        "inbounds": inbound_cnt,
        "outbounds": outbounds.into_iter().map(|(n,k)| json!({"name":n,"kind":k})).collect::<Vec<_>>(),
        "fingerprint": env!("CARGO_PKG_VERSION"),
        "selector_bound": selector_ok,
        "admin": { "enabled": admin_enabled, "token": token_present }
    });
    println!("{}", serde_json::to_string_pretty(&obj).unwrap());
}
