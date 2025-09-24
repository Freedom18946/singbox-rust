use crate::admin_debug::http_util::{parse_query, respond, respond_json_error, validate_inline_size_estimate, validate_decoded_size};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use tokio::io::AsyncWriteExt;

pub async fn handle(path_q: &str, sock: &mut (impl AsyncWriteExt + Unpin)) -> std::io::Result<()> {
    if !path_q.starts_with("/router/rules/normalize") {
        return Ok(());
    }

    let q = path_q.splitn(2, '?').nth(1).unwrap_or("");
    let params = parse_query(q);

    let text = if let Some(b64) = params.get("inline") {
        // Validate size estimate before decoding
        if let Err(_) = validate_inline_size_estimate(b64) {
            return respond_json_error(sock, 413, "inline content too large", Some("maximum size is 512KB")).await;
        }

        let bytes: Vec<u8> = match STANDARD.decode(b64.as_bytes()) {
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
            // TODO: Implement rules capture functionality
            String::new()
        }
        #[cfg(not(feature = "rules_capture"))]
        {
            String::new()
        }
    };

    if text.is_empty() {
        return respond_json_error(sock, 400, "no rules text provided", Some("provide rules via ?inline parameter")).await;
    }

    // For now, return the input text as-is
    // TODO: Implement actual rules normalization
    let out = format!("# Normalized rules (placeholder)\n{}", text);
    respond(sock, 200, "text/plain", &out).await
}
