use serde::Serialize;

#[derive(Serialize, Debug, Clone)]
pub struct BuildInfo {
    pub name: &'static str,
    pub version: &'static str,
    pub git_sha: &'static str,
    pub build_ts: &'static str,
}

#[must_use] 
pub const fn current() -> BuildInfo {
    BuildInfo {
        name: env!("CARGO_PKG_NAME"),
        version: env!("CARGO_PKG_VERSION"),
        git_sha: env!("GIT_SHA"),
        build_ts: env!("BUILD_TS"),
    }
}
