use crate::snapshot::NormalizedSnapshot;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FailureCategory {
    RateLimit,
    Network,
    Tls,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttributionResult {
    pub action_name: String,
    pub category: FailureCategory,
    pub evidence: String,
}

/// Classify env_limited failures from a snapshot into categories.
/// Rules:
/// - HTTP 403/429/503 status codes → RateLimit
/// - "connection refused" / "timeout" / "connect error" in error message → Network
/// - "tls" / "handshake" / "certificate" in error message → Tls
/// - Everything else → Unknown
pub fn classify_env_limited_failures(snapshot: &NormalizedSnapshot) -> Vec<AttributionResult> {
    let mut results = Vec::new();

    // Check traffic results that failed
    for traffic in &snapshot.traffic_results {
        if traffic.success {
            continue;
        }
        let detail_str = traffic.detail.to_string().to_lowercase();
        let category = classify_detail(&detail_str);
        let evidence = extract_evidence(&detail_str, &category);
        results.push(AttributionResult {
            action_name: traffic.name.clone(),
            category,
            evidence,
        });
    }

    // Check snapshot errors
    for error in &snapshot.errors {
        let msg = error.message.to_lowercase();
        let category = classify_detail(&msg);
        let evidence = extract_evidence(&msg, &category);
        results.push(AttributionResult {
            action_name: error.stage.clone(),
            category,
            evidence,
        });
    }

    results
}

/// NOTE: The classification rules here are mirrored in shell script
/// `scripts/lib_env_classify.sh::_classify_env_limited_category()`.
/// If you change the rules here, update the shell version to stay in sync.
fn classify_detail(detail: &str) -> FailureCategory {
    // Rate limit patterns
    if detail.contains("\"status\":403")
        || detail.contains("\"status\":429")
        || detail.contains("\"status\":503")
        || detail.contains("status=403")
        || detail.contains("status=429")
        || detail.contains("status=503")
        || detail.contains("rate limit")
        || detail.contains("too many requests")
    {
        return FailureCategory::RateLimit;
    }

    // TLS patterns (check before network since TLS failures can also contain "timeout")
    if detail.contains("tls")
        || detail.contains("handshake")
        || detail.contains("certificate")
        || detail.contains("ssl")
    {
        return FailureCategory::Tls;
    }

    // Network patterns
    if detail.contains("connection refused")
        || detail.contains("connect error")
        || detail.contains("timeout")
        || detail.contains("timed out")
        || detail.contains("network unreachable")
        || detail.contains("no route to host")
        || detail.contains("connection reset")
    {
        return FailureCategory::Network;
    }

    FailureCategory::Unknown
}

fn extract_evidence(detail: &str, category: &FailureCategory) -> String {
    match category {
        FailureCategory::RateLimit => {
            if detail.contains("403") {
                "HTTP 403".to_string()
            } else if detail.contains("429") {
                "HTTP 429".to_string()
            } else if detail.contains("503") {
                "HTTP 503".to_string()
            } else {
                "rate limit indicator".to_string()
            }
        }
        FailureCategory::Network => {
            if detail.contains("connection refused") {
                "connection refused".to_string()
            } else if detail.contains("timeout") || detail.contains("timed out") {
                "timeout".to_string()
            } else if detail.contains("connection reset") {
                "connection reset".to_string()
            } else {
                "network error".to_string()
            }
        }
        FailureCategory::Tls => {
            if detail.contains("handshake") {
                "TLS handshake failure".to_string()
            } else if detail.contains("certificate") {
                "certificate error".to_string()
            } else {
                "TLS error".to_string()
            }
        }
        FailureCategory::Unknown => "unclassified".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snapshot::{KernelKind, NormalizedError, NormalizedSnapshot, TrafficResult};
    use chrono::Utc;
    use serde_json::json;

    #[test]
    fn classify_rate_limit() {
        let now = Utc::now();
        let mut snap = NormalizedSnapshot::new("r".into(), "c".into(), KernelKind::Rust, now);
        snap.traffic_results.push(TrafficResult {
            name: "probe".into(),
            success: false,
            detail: json!({"status": 429, "error": "too many requests"}),
        });
        let results = classify_env_limited_failures(&snap);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].category, FailureCategory::RateLimit);
    }

    #[test]
    fn classify_network() {
        let now = Utc::now();
        let mut snap = NormalizedSnapshot::new("r".into(), "c".into(), KernelKind::Rust, now);
        snap.traffic_results.push(TrafficResult {
            name: "probe".into(),
            success: false,
            detail: json!({"error": "connection refused"}),
        });
        let results = classify_env_limited_failures(&snap);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].category, FailureCategory::Network);
    }

    #[test]
    fn classify_tls() {
        let now = Utc::now();
        let mut snap = NormalizedSnapshot::new("r".into(), "c".into(), KernelKind::Rust, now);
        snap.errors.push(NormalizedError {
            stage: "tls_check".into(),
            message: "TLS handshake failure: certificate expired".into(),
        });
        let results = classify_env_limited_failures(&snap);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].category, FailureCategory::Tls);
    }

    #[test]
    fn classify_unknown() {
        let now = Utc::now();
        let mut snap = NormalizedSnapshot::new("r".into(), "c".into(), KernelKind::Rust, now);
        snap.traffic_results.push(TrafficResult {
            name: "probe".into(),
            success: false,
            detail: json!({"error": "unexpected payload format"}),
        });
        let results = classify_env_limited_failures(&snap);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].category, FailureCategory::Unknown);
    }

    #[test]
    fn skip_successful_traffic() {
        let now = Utc::now();
        let mut snap = NormalizedSnapshot::new("r".into(), "c".into(), KernelKind::Rust, now);
        snap.traffic_results.push(TrafficResult {
            name: "ok".into(),
            success: true,
            detail: json!({"status": 200}),
        });
        let results = classify_env_limited_failures(&snap);
        assert!(results.is_empty());
    }
}
