#![cfg(feature = "explain")]
#![cfg_attr(feature = "strict_warnings", deny(warnings))]
use sb_core::routing::ExplainEngine;
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
    let mut _alpn: Option<String> = None;

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
                    _alpn = Some(args[i].clone());
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
    // 统一使用 routing::ExplainEngine 输出稳定字段集：dest/matched_rule/chain/outbound/trace
    let net = if proto == "udp" { "udp" } else { "tcp" };
    // 目的地优先级：--host | --sni | --ip 拼接端口
    let base_host = host_opt.or(sni).or_else(|| ip.map(|i| i.to_string()));
    let dest = if let Some(h) = base_host {
        format!("{}:{}", h, port)
    } else {
        format!("{}:{}", "", port)
    };

    // ExplainEngine 需要完整 Config；此工具作为开发辅助，允许使用空 ConfigIR（默认 direct）
    let cfg = sb_config::Config::default();
    let engine = ExplainEngine::from_config(&cfg).expect("explain engine");
    let res = engine.explain_with_network(&dest, net, true);

    match fmt {
        "dot" => {
            // 生成简化版 dot 输出（仅包含链路与命中规则）
            println!("digraph explain {{");
            println!(
                "  info [label=\"dest: {}\\noutbound: {}\\nrule:{}\"];",
                res.dest, res.outbound, res.matched_rule
            );
            for (idx, ch) in res.chain.iter().enumerate() {
                println!("  c{idx} [label=\"{}\"];", ch);
                if idx == 0 {
                    println!("  info -> c{idx};");
                } else {
                    println!("  c{} -> c{};", idx - 1, idx);
                }
            }
            println!("}}");
        }
        _ => {
            println!("{}", serde_json::to_string_pretty(&res).unwrap());
        }
    }
}
