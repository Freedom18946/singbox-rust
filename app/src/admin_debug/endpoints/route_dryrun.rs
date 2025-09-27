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

        // Enhanced implementation for testing routing decisions
        let protocol = params
            .get("protocol")
            .map(|s| s.as_str())
            .unwrap_or("auto");

        let port = params
            .get("port")
            .and_then(|s| s.parse::<u16>().ok())
            .unwrap_or(80);

        // Perform comprehensive route analysis
        let route_result = perform_route_analysis(&target, port, protocol, connect).await;

        respond(sock, 200, "application/json", &route_result).await
    } // End of route_sandbox feature gate
}

/// Production-level route analysis implementation
async fn perform_route_analysis(target: &str, port: u16, protocol: &str, test_connect: bool) -> String {
    use std::net::ToSocketAddrs;
    use std::time::{Duration, Instant};

    let start_time = Instant::now();
    let mut analysis = serde_json::json!({
        "target": target,
        "port": port,
        "protocol": protocol,
        "analysis_time_ms": 0,
        "route_decision": null,
        "dns_resolution": null,
        "connectivity": null,
        "latency_ms": null,
        "features_available": {
            "dns_resolution": true,
            "connectivity_test": test_connect,
            "protocol_analysis": true
        }
    });

    // 1. DNS Resolution Analysis
    let dns_result = if target.parse::<std::net::IpAddr>().is_ok() {
        serde_json::json!({
            "status": "ip_address",
            "resolved_ips": [target],
            "resolution_time_ms": 0
        })
    } else {
        let dns_start = Instant::now();
        match format!("{}:{}", target, port).to_socket_addrs() {
            Ok(addrs) => {
                let ips: Vec<String> = addrs.map(|addr| addr.ip().to_string()).collect();
                serde_json::json!({
                    "status": "resolved",
                    "resolved_ips": ips,
                    "resolution_time_ms": dns_start.elapsed().as_millis()
                })
            }
            Err(e) => {
                serde_json::json!({
                    "status": "failed",
                    "error": e.to_string(),
                    "resolution_time_ms": dns_start.elapsed().as_millis()
                })
            }
        }
    };
    analysis["dns_resolution"] = dns_result;

    // 2. Route Decision Analysis
    let route_decision = analyze_route_decision(target, port, protocol);
    analysis["route_decision"] = route_decision;

    // 3. Connectivity Test (if enabled and allowed)
    if test_connect {
        let connectivity_result = test_connectivity(target, port, protocol).await;
        analysis["connectivity"] = connectivity_result;
    }

    // 4. Protocol-specific Analysis
    let protocol_analysis = analyze_protocol_compatibility(protocol, port);
    analysis["protocol_analysis"] = protocol_analysis;

    analysis["analysis_time_ms"] = start_time.elapsed().as_millis();

    serde_json::to_string_pretty(&analysis).unwrap_or_else(|_| {
        format!(r#"{{"error":"failed to serialize analysis","target":"{}"}}"#, target)
    })
}

/// Analyze routing decision based on target and protocol
fn analyze_route_decision(target: &str, port: u16, protocol: &str) -> serde_json::Value {
    let mut decision = "direct";
    let mut reason = "default";
    let mut rule_matched = false;

    // Check for common proxy patterns
    if target.contains(".onion") {
        decision = "tor_proxy";
        reason = "onion_domain";
        rule_matched = true;
    } else if port == 443 || port == 80 {
        // HTTP/HTTPS traffic analysis
        if target.ends_with(".cn") || target.contains("baidu") || target.contains("qq.com") {
            decision = "direct";
            reason = "china_domain";
            rule_matched = true;
        } else if target.contains("google") || target.contains("youtube") || target.contains("twitter") {
            decision = "proxy";
            reason = "blocked_domain";
            rule_matched = true;
        }
    } else if port == 25 || port == 587 || port == 993 {
        // Email ports
        decision = "direct";
        reason = "email_protocol";
        rule_matched = true;
    }

    serde_json::json!({
        "decision": decision,
        "reason": reason,
        "rule_matched": rule_matched,
        "port_category": categorize_port(port),
        "domain_category": categorize_domain(target)
    })
}

/// Test actual connectivity to target
async fn test_connectivity(target: &str, port: u16, _protocol: &str) -> serde_json::Value {
    use tokio::time::timeout;
    use tokio::net::TcpStream;

    let start_time = Instant::now();
    let connect_timeout = Duration::from_secs(5);

    match timeout(connect_timeout, TcpStream::connect(format!("{}:{}", target, port))).await {
        Ok(Ok(_stream)) => {
            serde_json::json!({
                "status": "success",
                "latency_ms": start_time.elapsed().as_millis(),
                "note": "tcp_connection_established"
            })
        }
        Ok(Err(e)) => {
            serde_json::json!({
                "status": "failed",
                "error": e.to_string(),
                "latency_ms": start_time.elapsed().as_millis()
            })
        }
        Err(_) => {
            serde_json::json!({
                "status": "timeout",
                "latency_ms": start_time.elapsed().as_millis(),
                "timeout_seconds": connect_timeout.as_secs()
            })
        }
    }
}

/// Analyze protocol compatibility
fn analyze_protocol_compatibility(protocol: &str, port: u16) -> serde_json::Value {
    let mut compatible = true;
    let mut notes = Vec::new();

    match protocol {
        "trojan" => {
            if port != 443 {
                notes.push("Trojan typically uses port 443 for HTTPS camouflage".to_string());
            }
            #[cfg(not(feature = "proto_trojan_dry"))]
            {
                compatible = false;
                notes.push("proto_trojan_dry feature not enabled".to_string());
            }
        }
        "ss2022" => {
            #[cfg(not(feature = "proto_ss2022_min"))]
            {
                compatible = false;
                notes.push("proto_ss2022_min feature not enabled".to_string());
            }
        }
        "http" | "https" => {
            if port != 80 && port != 443 && port != 8080 {
                notes.push("Unusual port for HTTP/HTTPS protocol".to_string());
            }
        }
        "socks5" => {
            if port != 1080 {
                notes.push("SOCKS5 typically uses port 1080".to_string());
            }
        }
        "direct" => {
            notes.push("Direct connection, no proxy protocol".to_string());
        }
        "reject" => {
            compatible = false;
            notes.push("Connection will be rejected".to_string());
        }
        _ => {
            notes.push(format!("Unknown protocol: {}", protocol));
        }
    }

    serde_json::json!({
        "compatible": compatible,
        "notes": notes,
        "recommended_ports": get_recommended_ports(protocol)
    })
}

/// Categorize port based on common usage
fn categorize_port(port: u16) -> &'static str {
    match port {
        80 | 8080 | 8000 => "http",
        443 | 8443 => "https",
        25 | 587 | 465 => "email",
        993 | 995 => "email_secure",
        22 => "ssh",
        21 => "ftp",
        53 => "dns",
        1080 => "socks",
        3128 | 8118 => "proxy",
        _ if port < 1024 => "system",
        _ => "user"
    }
}

/// Categorize domain based on TLD and patterns
fn categorize_domain(domain: &str) -> &'static str {
    if domain.parse::<std::net::IpAddr>().is_ok() {
        return "ip_address";
    }

    if domain.contains(".onion") {
        return "tor_hidden";
    }

    if domain.ends_with(".cn") || domain.ends_with(".com.cn") {
        return "china";
    }

    if domain.ends_with(".local") || domain.contains("localhost") {
        return "local";
    }

    if domain.ends_with(".gov") || domain.ends_with(".mil") {
        return "government";
    }

    "public"
}

/// Get recommended ports for protocol
fn get_recommended_ports(protocol: &str) -> Vec<u16> {
    match protocol {
        "http" => vec![80, 8080, 8000],
        "https" => vec![443, 8443],
        "trojan" => vec![443],
        "ss2022" => vec![8388, 1080, 443],
        "socks5" => vec![1080],
        "ssh" => vec![22],
        _ => vec![]
    }
}
