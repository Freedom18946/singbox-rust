use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum KernelKind {
    Rust,
    Go,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedSnapshot {
    pub schema_version: u32,
    pub run_id: String,
    pub case_id: String,
    pub kernel: KernelKind,
    pub started_at: DateTime<Utc>,
    pub finished_at: DateTime<Utc>,
    pub http_results: Vec<HttpResult>,
    pub ws_frames: Vec<WsFrameCapture>,
    pub conn_summary: Option<Value>,
    pub traffic_counters: Option<TrafficCounters>,
    pub memory_series: Vec<MemoryPoint>,
    pub subscription_result: Option<SubscriptionResult>,
    pub traffic_results: Vec<TrafficResult>,
    pub errors: Vec<NormalizedError>,
    /// File descriptor count samples for leak detection (L10.2.2).
    #[serde(default)]
    pub fd_samples: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpResult {
    pub name: String,
    pub method: String,
    pub path: String,
    pub status: u16,
    #[serde(default)]
    pub body: Option<Value>,
    #[serde(default)]
    pub body_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WsFrameCapture {
    pub name: String,
    pub path: String,
    pub frames: Vec<Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficCounters {
    pub up: i64,
    pub down: i64,
    #[serde(default)]
    pub extra: BTreeMap<String, i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryPoint {
    pub inuse: i64,
    pub oslimit: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriptionResult {
    pub source_type: String,
    pub success: bool,
    pub format: String,
    pub node_count: usize,
    pub filtered_node_count: usize,
    pub protocols: Vec<String>,
    #[serde(default)]
    pub detail: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficResult {
    pub name: String,
    pub success: bool,
    pub detail: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NormalizedError {
    pub stage: String,
    pub message: String,
}

impl NormalizedSnapshot {
    pub fn new(
        run_id: String,
        case_id: String,
        kernel: KernelKind,
        started_at: DateTime<Utc>,
    ) -> Self {
        Self {
            schema_version: 1,
            run_id,
            case_id,
            kernel,
            started_at,
            finished_at: started_at,
            http_results: Vec::new(),
            ws_frames: Vec::new(),
            conn_summary: None,
            traffic_counters: None,
            memory_series: Vec::new(),
            subscription_result: None,
            traffic_results: Vec::new(),
            errors: Vec::new(),
            fd_samples: Vec::new(),
        }
    }
}
