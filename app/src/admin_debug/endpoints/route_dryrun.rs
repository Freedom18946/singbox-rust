use crate::admin_debug::http_util::{parse_query, respond, respond_json_error};
use tokio::io::AsyncWriteExt;

pub async fn handle(path_q: &str, sock: &mut (impl AsyncWriteExt + Unpin)) -> std::io::Result<()> {
    if !path_q.starts_with("/route/dryrun") {
        return Ok(());
    }

    #[cfg(not(feature = "route_sandbox"))]
    {
        return respond_json_error(sock, 501, "route_sandbox feature not enabled", Some("enable route_sandbox feature")).await;
    }

    #[cfg(feature = "route_sandbox")]
    {
        let q = path_q.splitn(2, '?').nth(1).unwrap_or("");
        let params = parse_query(q);

        // Check if network connection is allowed
        let allow_net = std::env::var("SB_ADMIN_ALLOW_NET")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        let connect = params
            .get("connect")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        if connect && !allow_net {
            return respond_json_error(sock, 403, "network connection not allowed", Some("set SB_ADMIN_ALLOW_NET=1 to enable networking")).await;
        }

        let target = params.get("target").cloned().unwrap_or_default();
        if target.is_empty() {
            return respond_json_error(sock, 400, "missing target parameter", Some("provide target in ?target parameter")).await;
        }

        // Placeholder implementation for different protocols
        let protocol = params
            .get("protocol")
            .map(|s| s.as_str())
            .unwrap_or("direct");

        let result = match protocol {
            "trojan" => {
                #[cfg(feature = "proto_trojan_dry")]
                {
                    format!(
                        r#"{{"target":"{}","protocol":"trojan","status":"offline_analysis","note":"trojan dry run available"}}"#,
                        target
                    )
                }
                #[cfg(not(feature = "proto_trojan_dry"))]
                {
                    format!(
                        r#"{{"target":"{}","protocol":"trojan","error":"proto_trojan_dry feature not enabled"}}"#,
                        target
                    )
                }
            }
            "ss2022" => {
                #[cfg(feature = "proto_ss2022_min")]
                {
                    format!(
                        r#"{{"target":"{}","protocol":"ss2022","status":"offline_analysis","note":"ss2022 min dry run available"}}"#,
                        target
                    )
                }
                #[cfg(not(feature = "proto_ss2022_min"))]
                {
                    format!(
                        r#"{{"target":"{}","protocol":"ss2022","error":"proto_ss2022_min feature not enabled"}}"#,
                        target
                    )
                }
            }
            "direct" => {
                format!(
                    r#"{{"target":"{}","protocol":"direct","status":"would_connect_directly"}}"#,
                    target
                )
            }
            "reject" => {
                format!(
                    r#"{{"target":"{}","protocol":"reject","status":"would_reject"}}"#,
                    target
                )
            }
            _ => {
                format!(
                    r#"{{"target":"{}","protocol":"{}","status":"unknown_protocol"}}"#,
                    target, protocol
                )
            }
        };

        respond(sock, 200, "application/json", &result).await
    } // End of route_sandbox feature gate
}
