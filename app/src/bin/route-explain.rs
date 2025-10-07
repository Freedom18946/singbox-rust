#![cfg(feature = "explain")]
#![cfg_attr(feature = "strict_warnings", deny(warnings))]
use sb_core::router::explain::{self, explain_decision, ExplainQuery};
use sb_core::router::RouterHandle;
use serde_json::Map;
use std::net::IpAddr;

fn main() {
    // 极简参数解析：--sni --ip --port --proto --format json|dot
    let args: Vec<String> = std::env::args().collect();
    let mut sni = None;
    let mut ip = None;
    let mut host_opt: Option<String> = None;
    let mut port = 0u16;
    let mut proto = "tcp";
    let mut fmt = "json";
    let mut alpn: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--sni" => {
                i += 1;
                if i < args.len() {
                    sni = Some(args[i].clone());
                }
            }
            "--ip" => {
                i += 1;
                if i < args.len() {
                    ip = args[i].parse::<IpAddr>().ok();
                }
            }
            "--host" => {
                i += 1;
                if i < args.len() {
                    host_opt = Some(args[i].clone());
                }
            }
            "--port" => {
                i += 1;
                if i < args.len() {
                    port = args[i].parse::<u16>().unwrap_or(0);
                }
            }
            "--proto" => {
                i += 1;
                if i < args.len() {
                    proto = Box::leak(args[i].clone().into_boxed_str());
                }
            }
            "--format" => {
                i += 1;
                if i < args.len() {
                    fmt = Box::leak(args[i].clone().into_boxed_str());
                }
            }
            "--alpn" => {
                i += 1;
                if i < args.len() {
                    alpn = Some(args[i].clone());
                }
            }
            "--json" => {
                fmt = "json";
            }
            "--dot" => {
                fmt = "dot";
            }
            _ => {}
        }
        i += 1;
    }
    // 使用运行时环境构建 RouterHandle（共享索引，无副作用）
    let router: RouterHandle = RouterHandle::from_env();

    let r = explain_decision(
        &router,
        ExplainQuery {
            sni: sni.clone(),
            host: host_opt.or(sni),
            ip,
            port,
            proto,
            transport: None,
            alpn,
        },
    );

    match fmt {
        "dot" => {
            println!("digraph explain {{");
            println!("  decision [label=\"decision: {}\"];", r.phase);
            for (idx, s) in r.steps.iter().enumerate() {
                println!(
                    "  n{idx} [label=\"{}\\nrule:{}\\nmatched:{}\\n{}\"];",
                    s.phase, s.rule_id, s.matched, s.reason
                );
                if idx > 0 {
                    println!("  n{} -> n{};", idx - 1, idx);
                }
            }
            println!("}}");
        }
        _ => {
            // Extra log hints for quick eyeballing
            tracing::info!(target: "app::route-explain", decision = %r.phase, "decision");
            if let Some(s) = r.steps.iter().find(|s| s.matched) {
                tracing::info!(
                    target: "app::route-explain",
                    phase = %s.phase,
                    rule_id = %s.rule_id,
                    reason = %s.reason,
                    "first_match"
                );
            }
            let trace = Map::new();
            let envelope = explain::envelope_from_result(&r, trace);
            println!("{}", serde_json::to_string_pretty(&envelope).unwrap());
        }
    }
}
