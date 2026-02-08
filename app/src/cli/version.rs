use crate::cli::buildinfo;
use crate::cli::output;
use crate::cli::VersionArgs;
use anyhow::Result;
use serde::Serialize;

#[derive(Serialize, Debug)]
pub struct VersionInfo {
    pub version: String,
    pub environment: String,
    pub tags: Vec<String>,
    /// Revision (git commit hash).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub revision: String,
}

pub fn run(args: VersionArgs) -> Result<()> {
    let build = buildinfo::current();

    // Collect enabled features from build environment
    let tags = collect_features();

    let environment = format!(
        "rust {}, {}/{}",
        rustc_version(),
        std::env::consts::OS,
        std::env::consts::ARCH,
    );

    let version_info = VersionInfo {
        version: build.version.to_string(),
        environment,
        tags,
        revision: build.git_sha.to_string(),
    };

    output::emit(
        args.format,
        || {
            let mut out = format!("sing-box version {}", version_info.version);
            if !version_info.revision.is_empty() {
                out.push_str(&format!(" ({})", version_info.revision));
            }
            out.push_str(&format!("\n\nEnvironment: {}", version_info.environment));
            if !version_info.tags.is_empty() {
                out.push_str(&format!("\nTags: {}", version_info.tags.join(",")));
            }
            out
        },
        &version_info,
    );

    Ok(())
}

fn rustc_version() -> &'static str {
    option_env!("RUSTC_VERSION").unwrap_or(env!("CARGO_PKG_RUST_VERSION"))
}

/// Collect enabled features from cargo feature flags
#[must_use]
pub fn collect_features() -> Vec<String> {
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
