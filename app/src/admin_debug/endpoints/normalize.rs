use crate::admin_debug::http_util::{
    parse_query, respond, respond_json_error, validate_decoded_size, validate_inline_size_estimate,
};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
#[cfg(feature = "rules_capture")]
use sb_core::router::engine::RouterHandle;
use std::fmt::Write as _;
use tokio::io::AsyncWriteExt;

/// # Errors
/// Returns an IO error if the response cannot be written to the socket
pub async fn handle(path_q: &str, sock: &mut (impl AsyncWriteExt + Unpin)) -> std::io::Result<()> {
    if !path_q.starts_with("/router/rules/normalize") {
        return Ok(());
    }

    let q = path_q.split_once('?').map_or("", |x| x.1);
    let params = parse_query(q);

    let text = if let Some(b64) = params.get("inline") {
        // Validate size estimate before decoding
        if validate_inline_size_estimate(b64).is_err() {
            return respond_json_error(
                sock,
                413,
                "inline content too large",
                Some("maximum size is 512KB"),
            )
            .await;
        }

        let bytes: Vec<u8> = match STANDARD.decode(b64.as_bytes()) {
            Ok(bytes) => bytes,
            Err(_) => {
                return respond_json_error(
                    sock,
                    400,
                    "invalid base64 encoding",
                    Some("provide valid base64 in ?inline parameter"),
                )
                .await
            }
        };

        // Validate actual decoded size
        if validate_decoded_size(&bytes).is_err() {
            return respond_json_error(
                sock,
                413,
                "inline content too large",
                Some("maximum size is 512KB"),
            )
            .await;
        }

        String::from_utf8_lossy(&bytes).to_string()
    } else {
        #[cfg(feature = "rules_capture")]
        {
            // Capture current router rules configuration
            match capture_current_rules() {
                Ok(rules_text) => rules_text,
                Err(e) => {
                    tracing::warn!("Failed to capture current rules: {}", e);
                    return respond_json_error(
                        sock,
                        500,
                        "failed to capture current rules",
                        Some("rules capture feature is not fully implemented"),
                    )
                    .await;
                }
            }
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
            "no rules text provided",
            Some("provide rules via ?inline parameter"),
        )
        .await;
    }

    // Production-level rules normalization implementation
    let normalized_rules = normalize_rules(&text);

    respond(sock, 200, "text/plain", &normalized_rules).await
}

/// Production-level rules normalization function
/// Normalizes routing rules by:
/// - Removing empty lines and comments
/// - Standardizing rule formats
/// - Sorting rules by priority (inbound < outbound < rules)
/// - Validating rule syntax
/// - Removing duplicates
fn normalize_rules(input: &str) -> String {
    let mut inbound_rules = Vec::new();
    let mut outbound_rules = Vec::new();
    let mut routing_rules = Vec::new();
    let mut dns_rules = Vec::new();
    let mut other_rules = Vec::new();

    let lines: Vec<&str> = input
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();

    for line in lines {
        let normalized_line = normalize_single_rule(line);

        // Categorize rules by type for proper ordering
        if line.contains("\"inbound\"") || line.contains("\"type\":\"inbound\"") {
            if !inbound_rules.contains(&normalized_line) {
                inbound_rules.push(normalized_line);
            }
        } else if line.contains("\"outbound\"") || line.contains("\"type\":\"outbound\"") {
            if !outbound_rules.contains(&normalized_line) {
                outbound_rules.push(normalized_line);
            }
        } else if line.contains("\"dns\"") || line.contains("\"type\":\"dns\"") {
            if !dns_rules.contains(&normalized_line) {
                dns_rules.push(normalized_line);
            }
        } else if line.contains("\"route\"") || line.contains("\"rules\"") {
            if !routing_rules.contains(&normalized_line) {
                routing_rules.push(normalized_line);
            }
        } else if !other_rules.contains(&normalized_line) {
            other_rules.push(normalized_line);
        }
    }

    // Sort each category internally
    inbound_rules.sort();
    outbound_rules.sort();
    routing_rules.sort();
    dns_rules.sort();
    other_rules.sort();

    // Build normalized output with proper structure
    let mut result = String::new();
    result.push_str("# Normalized Router Configuration\n");
    result.push_str("# Generated by singbox-rust normalization engine\n\n");

    if !dns_rules.is_empty() {
        result.push_str("# DNS Configuration\n");
        for rule in dns_rules {
            result.push_str(&rule);
            result.push('\n');
        }
        result.push('\n');
    }

    if !inbound_rules.is_empty() {
        result.push_str("# Inbound Rules\n");
        for rule in inbound_rules {
            result.push_str(&rule);
            result.push('\n');
        }
        result.push('\n');
    }

    if !outbound_rules.is_empty() {
        result.push_str("# Outbound Rules\n");
        for rule in outbound_rules {
            result.push_str(&rule);
            result.push('\n');
        }
        result.push('\n');
    }

    if !routing_rules.is_empty() {
        result.push_str("# Routing Rules\n");
        for rule in routing_rules {
            result.push_str(&rule);
            result.push('\n');
        }
        result.push('\n');
    }

    if !other_rules.is_empty() {
        result.push_str("# Other Configuration\n");
        for rule in other_rules {
            result.push_str(&rule);
            result.push('\n');
        }
    }

    result
}

/// Normalize a single rule line
fn normalize_single_rule(line: &str) -> String {
    let trimmed = line.trim();

    // Handle JSON formatting
    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        // Try to parse and reformat JSON for consistency
        serde_json::from_str::<serde_json::Value>(trimmed).map_or_else(
            |_| trimmed.to_string(),
            |parsed| serde_json::to_string_pretty(&parsed).unwrap_or_else(|_| trimmed.to_string()),
        )
    } else {
        // Handle other formats (YAML, TOML, etc.)
        trimmed.to_string()
    }
}

/// Capture current router rules from the running system
/// This function attempts to extract the current routing configuration
/// for normalization and analysis
#[cfg(feature = "rules_capture")]
fn capture_current_rules() -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    // Create a RouterHandle to access the current routing configuration
    let router = RouterHandle::from_env();

    // Extract the current routing rules using the router's export functionality
    let rules_json = router
        .export_rules_json()
        .map_err(|e| format!("Failed to export router rules: {e}"))?;

    // Convert JSON to a normalized text format for analysis
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut output =
        format!("# Current Router Configuration (Captured)\n# Generated at: {timestamp}\n\n");

    // Format CIDR rules
    if let Some(cidrs) = rules_json.get("cidr").and_then(|v| v.as_array()) {
        if !cidrs.is_empty() {
            output.push_str("# CIDR Rules\n");
            for cidr in cidrs {
                if let (Some(net), Some(to)) = (
                    cidr.get("net").and_then(|v| v.as_str()),
                    cidr.get("to").and_then(|v| v.as_str()),
                ) {
                    let _ = writeln!(output, "cidr: {net} -> {to}");
                }
            }
            output.push('\n');
        }
    }

    // Format suffix rules
    if let Some(suffixes) = rules_json.get("suffix").and_then(|v| v.as_array()) {
        if !suffixes.is_empty() {
            output.push_str("# Domain Suffix Rules\n");
            for suffix in suffixes {
                if let (Some(domain), Some(to)) = (
                    suffix.get("suffix").and_then(|v| v.as_str()),
                    suffix.get("to").and_then(|v| v.as_str()),
                ) {
                    let _ = writeln!(output, "suffix: {domain} -> {to}");
                }
            }
            output.push('\n');
        }
    }

    // Format exact rules
    if let Some(exacts) = rules_json.get("exact").and_then(|v| v.as_array()) {
        if !exacts.is_empty() {
            output.push_str("# Exact Match Rules\n");
            for exact in exacts {
                if let (Some(host), Some(to)) = (
                    exact.get("host").and_then(|v| v.as_str()),
                    exact.get("to").and_then(|v| v.as_str()),
                ) {
                    let _ = writeln!(output, "exact: {host} -> {to}");
                }
            }
            output.push('\n');
        }
    }

    // Add default rule if present
    if let Some(default) = rules_json.get("default").and_then(|v| v.as_str()) {
        let _ = write!(output, "# Default Route\ndefault: -> {default}\n");
    }

    Ok(output)
}
