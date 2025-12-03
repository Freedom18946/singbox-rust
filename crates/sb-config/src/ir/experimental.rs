use serde::{Deserialize, Serialize};
/// Experimental configuration options.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ExperimentalIR {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_file: Option<CacheFileIR>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clash_api: Option<ClashApiIR>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v2ray_api: Option<V2RayApiIR>,
}

/// Cache file configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CacheFileIR {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default)]
    pub store_fakeip: bool,
    #[serde(default)]
    pub store_rdrc: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rdrc_timeout: Option<String>,
}

/// Clash API configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ClashApiIR {
    #[serde(default)]
    pub external_controller: Option<String>,
    #[serde(default)]
    pub external_ui: Option<String>,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(default)]
    pub external_ui_download_url: Option<String>,
    #[serde(default)]
    pub external_ui_download_detour: Option<String>,
    #[serde(default)]
    pub default_mode: Option<String>,
}

/// V2Ray API configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct V2RayApiIR {
    #[serde(default)]
    pub listen: Option<String>,
    #[serde(default)]
    pub stats: Option<StatsIR>,
}

/// V2Ray stats configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct StatsIR {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub inbound: bool,
    #[serde(default)]
    pub outbound: bool,
    #[serde(default)]
    pub users: Vec<String>,
}
