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

pub async fn handle(sock: &mut (impl AsyncWriteExt + Unpin)) -> std::io::Result<()> {
    let pid = std::process::id();
    let uptime_secs = proc_uptime();
    // 在未启用 router/sbcore_rules_tool 时提供空集，避免特性未开启导致的编译错误
    #[cfg(any(feature = "router", feature = "sbcore_rules_tool"))]
    let kinds = crate::analyze::registry::supported_kinds();
    #[cfg(not(any(feature = "router", feature = "sbcore_rules_tool")))]
    let kinds: Vec<&'static str> = vec![];

    #[cfg(any(feature = "router", feature = "sbcore_rules_tool"))]
    let async_kinds = crate::analyze::registry::supported_async_kinds();
    #[cfg(not(any(feature = "router", feature = "sbcore_rules_tool")))]
    let async_kinds: Vec<&'static str> = vec![];
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
        uptime_secs,
        supported_kinds_count: kinds.len(),
        supported_async_kinds_count: async_kinds.len(),
        security: crate::admin_debug::security_metrics::snapshot(),
        auth_mode,
        mtls_status,
        audit_latest_ts: crate::admin_debug::audit::latest_ts(),
        config_version: crate::admin_debug::reloadable::version(),
    };
    let body = serde_json::to_string(&h).unwrap_or_else(|_| "{}".into());
    crate::admin_debug::http_util::respond(sock, 200, "application/json", &body).await
}

fn proc_uptime() -> u64 {
    crate::admin_debug::http_server::START
        .get()
        .map(|t| t.elapsed().as_secs())
        .unwrap_or(0)
}
