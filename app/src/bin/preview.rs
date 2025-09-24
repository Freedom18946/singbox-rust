#![cfg_attr(feature = "strict_warnings", deny(warnings))]
//! sb-preview：离线路由预演（不触全局状态，不需要运行主服务）
//! 依赖：features = ["preview_route"]
use anyhow::{anyhow, Result};
use clap::{Parser, ValueEnum};
use std::{fs, path::PathBuf};

#[derive(ValueEnum, Clone, Debug)]
enum Proto {
    Tcp,
    Udp,
}

#[derive(Parser, Debug)]
#[command(
    name = "sb-preview",
    version,
    about = "Offline Router Preview (explain)"
)]
struct Opt {
    /// DSL 规则文件（标准 DSL；若启用 --dsl-plus，则支持 include/macro）
    #[arg(short = 'f', long = "dsl")]
    dsl_file: PathBuf,
    /// 目标（host[:port]），如 example.com:443
    #[arg(short = 't', long = "target")]
    target: String,
    /// 协议：tcp|udp（默认 tcp）
    #[arg(long="proto", value_enum, default_value_t=Proto::Tcp)]
    proto: Proto,
    /// 输出格式：json|min|pretty —— json 为结构化 explain，min 为 decision-only
    #[arg(long, default_value = "json")]
    fmt: String,
}

fn main() -> Result<()> {
    let opt = Opt::parse();
    let dsl = fs::read_to_string(&opt.dsl_file)
        .map_err(|e| anyhow!("无法读取 DSL 文件：{}: {e}", opt.dsl_file.display()))?;

    // 1) 构建临时 RouterIndex
    // 默认标准 DSL；若编译时启用了 dsl_plus feature，则尝试环境开关 SB_DSL_PLUS=1
    let use_plus = std::env::var("SB_DSL_PLUS").ok().as_deref() == Some("1");
    let idx = {
        #[cfg(feature = "dsl_plus")]
        {
            if use_plus {
                sb_core::router::preview::build_index_from_rules_plus(
                    &dsl,
                    opt.dsl_file.parent().map(|p| p.as_ref()),
                )
            } else {
                sb_core::router::preview::build_index_from_rules(&dsl)
            }
        }
        #[cfg(not(feature = "dsl_plus"))]
        {
            sb_core::router::preview::build_index_from_rules(&dsl)
        }
    }
    .map_err(|e| anyhow!("构建路由索引失败：{e}"))?;

    // 2) 预演决策（explain）
    let ex = match opt.proto {
        Proto::Tcp => sb_core::router::preview::preview_decide_http(&idx, &opt.target),
        Proto::Udp => sb_core::router::preview::preview_decide_udp(&idx, &opt.target),
    };

    // 3) 输出
    if opt.fmt == "min" {
        println!("{}", ex.decision);
    } else {
        // 标准结构：{ decision, reason, reason_kind }
        let j = sb_core::router::minijson::obj([
            (
                "decision",
                sb_core::router::minijson::Val::Str(&ex.decision),
            ),
            ("reason", sb_core::router::minijson::Val::Str(&ex.reason)),
            (
                "reason_kind",
                sb_core::router::minijson::Val::Str(&ex.reason_kind),
            ),
        ]);
        if opt.fmt == "pretty" {
            // 尝试美化：minijson -> serde_json 中转
            let s = j.to_string();
            match serde_json::from_str::<serde_json::Value>(&s) {
                Ok(v) => println!("{}", serde_json::to_string_pretty(&v).unwrap_or_else(|_| s)),
                Err(_) => println!("{j}"),
            }
        } else {
            println!("{j}");
        }
    }
    Ok(())
}
