use crate::admin_debug::http_util::{parse_query, respond, respond_json_error};
use tokio::io::AsyncWriteExt;

/// # Errors
/// Returns an IO error if the response cannot be written to the socket
pub async fn handle(path_q: &str, sock: &mut (impl AsyncWriteExt + Unpin)) -> std::io::Result<()> {
    if !path_q.starts_with("/router/geoip") {
        return Ok(());
    }

    let q = path_q.split_once('?').map_or("", |x| x.1);
    let params = parse_query(q);
    let ip_s = params.get("ip").cloned().unwrap_or_default();

    if let Ok(ip) = ip_s.parse::<std::net::IpAddr>() {
        // Try to use geoip functionality if available
        #[cfg(feature = "router")]
        let body = {
            // For now, provide a minimal implementation
            // In the future, this should integrate with sb-core geoip
            format!(
                r#"{{"ip":"{ip}","cc":"Unknown","note":"GeoIP not implemented"}}"#
            )
        };

        #[cfg(not(feature = "router"))]
        let body = format!(r#"{{"ip":"{}","unavailable":true}}"#, ip);

        respond(sock, 200, "application/json", &body).await
    } else {
        respond_json_error(
            sock,
            400,
            "invalid IP address",
            Some("provide valid IP in ?ip parameter"),
        )
        .await
    }
}
