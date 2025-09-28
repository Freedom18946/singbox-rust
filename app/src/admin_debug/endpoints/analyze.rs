use crate::admin_debug::http_util::{parse_query, respond, respond_json_error, validate_inline_size_estimate, validate_decoded_size, supported_patch_kinds};
#[cfg(any(feature="router", feature="sbcore_rules_tool"))]
use crate::analyze::registry::{build_by_kind, build_by_kind_async, supported_kinds};
use base64::Engine;
use tokio::io::AsyncWriteExt;

/// Build a single patch based on kind, prioritizing async, delegating to registry
#[cfg(any(feature="router", feature="sbcore_rules_tool"))]
async fn build_single_patch_json_async(
    kind: &str,
    report: &sb_core::router::analyze::Report,
    text: &str,
    file: Option<&str>,
) -> anyhow::Result<(serde_json::Value, bool)> {
    // Create input payload for registry
    let input = serde_json::json!({
        "kind": kind,
        "report": serde_json::to_value(report).unwrap_or_default(),
        "text": text,
        "file": file
    });

    // Try async first, fallback to sync
    match build_by_kind_async(kind, &input).await {
        Ok(result) => Ok((result, true)),
        Err(_) => match build_by_kind(kind, &input) {
            Ok(result) => Ok((result, false)),
            Err(e) => Err(e),
        }
    }
}

/// Legacy fallback for when registry features are disabled
#[cfg(not(any(feature="router", feature="sbcore_rules_tool")))]
fn build_single_patch_json(
    kind: &str,
    _report: &sb_core::router::analyze::Report,
    _text: &str,
    _file: Option<&str>,
) -> anyhow::Result<serde_json::Value> {
    anyhow::bail!("registry not available, kind: {}", kind);
}

pub async fn handle(path_q: &str, sock: &mut (impl AsyncWriteExt + Unpin)) -> std::io::Result<()> {
    if !path_q.starts_with("/router/analyze") {
        return Ok(());
    }

    let q = path_q.splitn(2, '?').nth(1).unwrap_or("");
    let _params = parse_query(q);

    if path_q.starts_with("/router/analyze/kinds") {
        #[cfg(feature = "sbcore_rules_tool")]
        {
            let body = sb_core::router::analyze_fix::supported_patch_kinds_json();
            respond(sock, 200, "application/json", &body).await
        }
        #[cfg(not(feature = "sbcore_rules_tool"))]
        {
            respond_json_error(
                sock,
                501,
                "sbcore_rules_tool feature not enabled",
                Some("enable sbcore_rules_tool feature"),
            )
            .await
        }
    } else if path_q.starts_with("/router/analyze/patch") {
        #[cfg(feature = "sbcore_rules_tool")]
        {
            let params = parse_query(q);
            let kind = params.get("kind").cloned().unwrap_or_default();

            if kind.is_empty() {
                return respond_json_error(sock, 400, "missing kind parameter", Some("provide kind in ?kind parameter")).await;
            }

            // Validate that the kind is supported
            let supported = supported_patch_kinds();
            if !supported.iter().any(|s| s.as_str() == kind) {
                let supported_list = supported.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ");
                let hint = format!("supported kinds: [{}]", supported_list);
                return respond_json_error(sock, 400, "unsupported patch kind", Some(&hint)).await;
            }

            let text = if let Some(b64) = params.get("inline") {
                // Validate size estimate before decoding
                if let Err(_) = validate_inline_size_estimate(b64) {
                    return respond_json_error(sock, 413, "inline content too large", Some("maximum size is 512KB")).await;
                }

                let bytes = match base64::engine::general_purpose::STANDARD.decode(b64.as_bytes()) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        return respond_json_error(sock, 400, "invalid base64 encoding", Some("provide valid base64 in ?inline parameter")).await
                    }
                };

                // Validate actual decoded size
                if let Err(_) = validate_decoded_size(&bytes) {
                    return respond_json_error(sock, 413, "inline content too large", Some("maximum size is 512KB")).await;
                }

                String::from_utf8_lossy(&bytes).to_string()
            } else {
                #[cfg(feature = "rules_capture")]
                {
                    sb_core::router::router_captured_rules().unwrap_or_default()
                }
                #[cfg(not(feature = "rules_capture"))]
                {
                    String::new()
                }
            };

            if text.is_empty() {
                return respond_json_error(
                    sock,
                    400,
                    "no rules text available",
                    Some("use ?inline=base64 or enable rules_capture"),
                )
                .await;
            }

            let report = sb_core::router::analyze::analyze(&text);

            match build_single_patch_json_async(&kind, &report, &text, Some("rules.conf")).await {
                Ok((patch_json, used_async)) => {
                    let response = serde_json::json!({
                        "ok": patch_json.get("error").is_none(),
                        "kind": kind,
                        "async": used_async,
                        "patch": patch_json
                    });
                    let body = serde_json::to_string(&response).unwrap_or_else(|_| "{}".to_string());
                    respond(sock, 200, "application/json", &body).await
                }
                Err(e) => {
                    let supported_list = supported_kinds().join(", ");
                    let hint = format!("supported kinds: [{}]", supported_list);
                    respond_json_error(
                        sock,
                        400,
                        &format!("patch build failed: {}", e),
                        Some(&hint),
                    ).await
                }
            }
        }
        #[cfg(not(feature = "sbcore_rules_tool"))]
        {
            respond_json_error(
                sock,
                501,
                "sbcore_rules_tool feature not enabled",
                Some("enable sbcore_rules_tool feature"),
            )
            .await
        }
    } else if path_q == "/router/analyze" {
        // Main analyze endpoint
        let params = parse_query(q);
        let text = if let Some(b64) = params.get("inline") {
            // Validate size estimate before decoding
            if let Err(_) = validate_inline_size_estimate(b64) {
                return respond_json_error(sock, 413, "inline content too large", Some("maximum size is 512KB")).await;
            }

            let bytes = match base64::engine::general_purpose::STANDARD.decode(b64.as_bytes()) {
                Ok(bytes) => bytes,
                Err(_) => return respond_json_error(sock, 400, "invalid base64 encoding", Some("provide valid base64 in ?inline parameter")).await,
            };

            // Validate actual decoded size
            if let Err(_) = validate_decoded_size(&bytes) {
                return respond_json_error(sock, 413, "inline content too large", Some("maximum size is 512KB")).await;
            }

            String::from_utf8_lossy(&bytes).to_string()
        } else {
            #[cfg(feature = "rules_capture")]
            {
                sb_core::router::router_captured_rules().unwrap_or_default()
            }
            #[cfg(not(feature = "rules_capture"))]
            {
                String::new()
            }
        };

        if text.is_empty() {
            return respond_json_error(
                sock,
                400,
                "no rules text available",
                Some("use ?inline=base64 or enable rules_capture"),
            )
            .await;
        }

        let report = sb_core::router::analyze::analyze(&text);

        #[cfg(feature = "sbcore_analyze_json")]
        {
            let body = report.to_json();
            respond(sock, 200, "application/json", &body).await
        }
        #[cfg(not(feature = "sbcore_analyze_json"))]
        {
            let body = report.to_minijson();
            respond(sock, 200, "application/json", &body).await
        }
    } else {
        respond_json_error(sock, 404, "unknown analyze endpoint", None).await
    }
}
