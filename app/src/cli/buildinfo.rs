use serde::Serialize;

#[derive(Serialize, Debug, Clone)]
pub struct BuildInfo {
    pub name: &'static str,
    pub version: &'static str,
    pub git_sha: &'static str,
    pub build_ts: &'static str,
}

pub fn current() -> BuildInfo {
    BuildInfo {
        name: env!("CARGO_PKG_NAME"),
        version: env!("CARGO_PKG_VERSION"),
        git_sha: env!("GIT_SHA"),
        build_ts: env!("BUILD_TS"),
    }
}