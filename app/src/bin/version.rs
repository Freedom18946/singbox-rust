use serde_json::json;
use app::cli::{buildinfo, json as cli_json};

fn main() {
    // 注意：features 可按需扩展（通过 cfg! 宏与 env 变量）
    let mut feats = vec![];
    if cfg!(feature = "schema-v2") {
        feats.push("schema-v2");
    }
    if cfg!(feature = "tls-rustls") {
        feats.push("tls-rustls");
    }
    let bi = buildinfo::current();
    let obj = json!({
        "name": env!("CARGO_PKG_NAME"),
        "version": env!("CARGO_PKG_VERSION"),
        "features": feats,
        "fingerprint": build_fingerprint(),
        "license": "Apache-2.0",
        "license_notice": "Licensed under the Apache License, Version 2.0. See LICENSES/THIRD-PARTY.md for third-party licenses.",
        "build_info": {
            "git_sha": bi.git_sha,
            "build_ts": bi.build_ts
        }
    });
    // 统一 helper 输出，后续 CLI 可共用
    cli_json::ok(&obj);
}

fn build_fingerprint() -> String {
    // 简化 fingerprint：版本 + 可用的构建时间；可替换为 git sha1
    format!(
        "{}-{}",
        env!("CARGO_PKG_VERSION"),
        option_env!("BUILD_TS").unwrap_or("dev")
    )
}
