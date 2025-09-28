use anyhow::Result;
use serde::Serialize;
use crate::cli::VersionArgs;
use crate::cli::buildinfo;
use crate::cli::output;

#[derive(Serialize, Debug)]
pub struct VersionInfo {
    pub name: String,
    pub version: String,
    pub commit: String,
    pub date: String,
    pub features: Vec<String>,
}

pub fn run(args: VersionArgs) -> Result<()> {
    let build = buildinfo::current();

    // Collect enabled features from build environment
    let features = collect_features();

    let version_info = VersionInfo {
        name: build.name.to_string(),
        version: build.version.to_string(),
        commit: build.git_sha.to_string(),
        date: build.build_ts.to_string(),
        features,
    };

    output::emit(args.format, || {
        format!("{} {} ({})\nBuilt: {}\nFeatures: {}",
            version_info.name,
            version_info.version,
            version_info.commit,
            version_info.date,
            version_info.features.join(", ")
        )
    }, &version_info);

    Ok(())
}

/// Collect enabled features from cargo feature flags
fn collect_features() -> Vec<String> {
    let mut features = Vec::new();

    #[cfg(feature = "router")]
    features.push("router".to_string());

    #[cfg(feature = "metrics")]
    features.push("metrics".to_string());

    #[cfg(feature = "admin_debug")]
    features.push("admin_debug".to_string());

    #[cfg(feature = "bench-cli")]
    features.push("bench-cli".to_string());

    #[cfg(feature = "dev-cli")]
    features.push("dev-cli".to_string());

    #[cfg(feature = "manpage")]
    features.push("manpage".to_string());

    #[cfg(feature = "reqwest")]
    features.push("reqwest".to_string());

    #[cfg(feature = "subs_http")]
    features.push("subs_http".to_string());

    features.sort();
    features
}