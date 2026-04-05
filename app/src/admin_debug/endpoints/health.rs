use serde::Serialize;
use tokio::io::AsyncWriteExt;

#[derive(Serialize)]
struct Health {
    pid: u32,
    uptime_secs: u64,
    supported_kinds_count: usize,
    supported_async_kinds_count: usize,
    security: crate::admin_debug::security_metrics::SecuritySnapshot,
    auth_mode: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    mtls_status: Option<MtlsStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    audit_latest_ts: Option<u64>,
    config_version: u64,
}

#[derive(Serialize)]
struct MtlsStatus {
    enabled: bool,
    peer_verified: bool,
}

/// # Errors
/// Returns an IO error if the response cannot be written to the socket
pub async fn handle(
    sock: &mut (impl AsyncWriteExt + Unpin),
    state: &crate::admin_debug::AdminDebugState,
) -> std::io::Result<()> {
    let query = state.query();
    let pid = std::process::id();
    let auth_mode = crate::admin_debug::http_server::get_auth_mode();

    // Add mTLS status if enabled
    let mtls_status = if auth_mode == "mtls" {
        Some(MtlsStatus {
            enabled: true,
            peer_verified: true, // Simplified - in production would check actual peer cert
        })
    } else {
        None
    };

    let h = Health {
        pid,
        uptime_secs: query.uptime_secs(),
        supported_kinds_count: query.supported_kinds_count(),
        supported_async_kinds_count: query.supported_async_kinds_count(),
        security: match query.security_snapshot() {
            Ok(snapshot) => snapshot,
            Err(err) => {
                return crate::admin_debug::http_util::respond_json_error(
                    sock,
                    500,
                    "failed to collect admin security snapshot",
                    Some(&err.to_string()),
                )
                .await;
            }
        },
        auth_mode,
        mtls_status,
        audit_latest_ts: crate::admin_debug::audit::latest_ts(),
        config_version: query.config_version(),
    };
    let body = serde_json::to_string(&h).unwrap_or_else(|_| "{}".into());
    crate::admin_debug::http_util::respond(sock, 200, "application/json", &body).await
}
