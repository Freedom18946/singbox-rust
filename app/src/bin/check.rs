#![cfg_attr(feature = "strict_warnings", deny(warnings))]
//! 最小可用配置校验工具（独立 bin，不侵入主流程）
//! 支持 JSON 与 YAML（自动判定），兼容 inbound 监听写法（顺序与 CLI help 一致）：
//!   1) { "listen":"127.0.0.1:1080" }
//!   2) { "listen":"127.0.0.1", "port":1080 }
//!   3) { "listen":"127.0.0.1", "listen_port":1080 }
//! 如需在每次启动 sb-subs 时自动体检本地文件：见 `--autoprobe` / `--autoprobe-default` 与 `SB_SUBS_AUTOPROBE`。
//! 如需对 DSL 分析做结构嗅探：见 `sb-route analyze --emit keys_only`。
//! 对比样本量大时：`sb-route compare --diff-sample 64 --diff-sample-mode random --seed 42` 可复现抽样。
//! 样本均衡：`--cluster-by reason_kind --max-per-cluster 8`，仅影响 samples，不影响矩阵。
use anyhow::{anyhow, Result};
use clap::Parser;
use serde_json::Value;
use serde_yaml;
#[allow(unused_imports)]
use std::fmt;
use std::{fs, path::PathBuf};

#[cfg(feature = "config_schema")]
use jsonschema;

#[derive(Parser, Debug)]
#[command(name = "sb-check", version, about = "singbox-rs config checker")]
struct Opt {
    /// 配置文件路径（自动识别 JSON 或 YAML）
    #[arg(short, long)]
    config: PathBuf,
    /// JSON Schema 文件路径，用于验证配置结构
    #[arg(long = "config-schema")]
    config_schema: Option<PathBuf>,
}

fn human_check(root: &Value) -> Result<()> {
    // 1) 根对象
    if !root.is_object() {
        return Err(anyhow!("$. (root) 不是对象：请提供 JSON 对象作为根"));
    }
    // 2) inbounds/outbounds 基本存在性
    for key in ["inbounds", "outbounds"] {
        let p = format!("$.{key}");
        let v = root
            .get(key)
            .ok_or_else(|| anyhow!("{p} 缺失：至少需要一个 {key} 条目"))?;
        if !v.is_array() {
            return Err(anyhow!("{p} 应为数组：示例 `\"{key}\": [{{ ... }}]`"));
        }
        if v.as_array().unwrap().is_empty() {
            return Err(anyhow!("{p} 为空：至少提供 1 个条目"));
        }
    }
    // 3) 逐个 inbound 最小字段（type + listen 表达之一）
    if let Some(arr) = root.get("inbounds").and_then(|x| x.as_array()) {
        for (i, v) in arr.iter().enumerate() {
            let base = format!("$.inbounds[{i}]");
            let t = v
                .get("type")
                .and_then(|x| x.as_str())
                .ok_or_else(|| anyhow!("{base}.type 缺失或不是字符串"))?;
            match t {
                "socks" | "http" => {
                    let listen = v
                        .get("listen")
                        .and_then(|x| x.as_str())
                        .ok_or_else(|| anyhow!("{base}.listen 缺失或不是字符串"))?;
                    let port_field = v
                        .get("port")
                        .and_then(|x| x.as_u64())
                        .or_else(|| v.get("listen_port").and_then(|x| x.as_u64()));
                    let ok = if listen.contains(':') {
                        true
                    } else {
                        port_field.is_some()
                    };
                    if !ok {
                        return Err(anyhow!(
                            "{base}: 需要 `listen=\"ip:port\"` 或 `listen=\"ip\" + (`port`|`listen_port`)`"
                        ));
                    }
                }
                other => {
                    tracing::warn!(target: "app::check", base = %base, kind = %other, "type not in minimal checklist; skip deep checks");
                }
            }
        }
    }
    Ok(())
}

fn main() -> Result<()> {
    let opt = Opt::parse();
    let raw = fs::read_to_string(&opt.config)?;
    let v: Value = match serde_json::from_str::<Value>(&raw) {
        Ok(v) => v,
        Err(e_json) => match serde_yaml::from_str::<Value>(&raw) {
            Ok(v) => v,
            Err(e_yaml) => {
                return Err(anyhow!(
                    "解析失败：既不是合法 JSON，也不是合法 YAML；\n  JSON 错误：{e_json}\n  YAML 错误：{e_yaml}"
                ));
            }
        },
    };

    // Schema validation (if provided)
    if let Some(_schema_path) = &opt.config_schema {
        #[cfg(feature = "config_schema")]
        {
            let schema_raw =
                fs::read_to_string(_schema_path).map_err(|e| anyhow!("读取 schema 文件失败：{e}"))?;
            let schema_json: Value =
                serde_json::from_str(&schema_raw).map_err(|e| anyhow!("解析 schema 文件失败：{e}"))?;

            let validator = jsonschema::Validator::new(&schema_json)
                .map_err(|e| anyhow!("编译 JSON Schema 失败：{e}"))?;

            let validation_result = validator.validate(&v);
            if validation_result.is_err() {
                let errors: Vec<String> = validation_result.unwrap_err()
                    .take(5)
                    .map(|e| format!("{}", e))
                    .collect();

                tracing::error!(target: "app::check", "配置 schema 验证失败");
                for (i, error) in errors.iter().enumerate() {
                    tracing::error!(target: "app::check", idx = i + 1, msg = %error, "schema validation error");
                }

                std::process::exit(2);
            }
        }
        #[cfg(not(feature = "config_schema"))]
        {
            anyhow::bail!("--config-schema 需要启用 'config_schema' feature（请以 `--features config_schema` 构建运行）");
        }
    }

    if let Err(e) = human_check(&v) {
        tracing::error!(target: "app::check", error = %e, "校验未通过");
        std::process::exit(2);
    }

    if opt.config_schema.is_some() {
        println!("OK: 配置通过 schema 验证和基本结构校验");
    } else {
        println!("OK: 基本结构与关键字段通过（JSON/YAML 兼容；更严格语义校验后续提供）");
    }
    Ok(())
}
