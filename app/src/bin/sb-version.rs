use app::cli::{buildinfo, json as cli_json};
use serde_json::json;

fn main() {
    // Emit the same JSON payload as the `version` binary for RC tooling compatibility
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
    cli_json::ok(&obj);
}

fn build_fingerprint() -> String {
    format!(
        "{}-{}",
        env!("CARGO_PKG_VERSION"),
        option_env!("BUILD_TS").unwrap_or("dev")
    )
}
