use app::cli::{buildinfo, version::collect_features};
use serde_json::json;

fn main() {
    // RC tooling expects a flat version info object without ok/data envelope.
    let bi = buildinfo::current();
    let features = collect_features();
    let obj = json!({
        "version": bi.version,
        "commit": bi.git_sha,
        "build_time": env!("SB_BUILD_TIME_EPOCH"),
        "features": features,
        "platform": {
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "target": env!("TARGET"),
        }
    });
    println!("{}", serde_json::to_string(&obj).unwrap());
}
