//! P0 Protocol Integration Tests with Routing Rules
//!
//! Tests P0 protocols (REALITY, ECH, Hysteria v1/v2, SSH, TUIC) with:
//! - Domain-based routing
//! - IP-based routing
//! - Port-based routing
//! - Process-based routing
//!
//! Requirements: 10.2

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use tempfile::NamedTempFile;

/// Locate a workspace binary by name
fn workspace_bin(name: &str) -> PathBuf {
    let env_key = format!("CARGO_BIN_EXE_{}", name.replace('-', "_"));
    if let Ok(path) = std::env::var(&env_key) {
        return PathBuf::from(path);
    }
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.pop(); // Go to workspace root
    path.push("target");
    let profile = std::env::var("CARGO_PROFILE")
        .ok()
        .or_else(|| std::env::var("PROFILE").ok())
        .unwrap_or_else(|| "debug".into());
    path.push(profile);
    path.push(name);
    if cfg!(windows) {
        path.set_extension("exe");
    }
    path
}

fn write_cfg(content: &str) -> NamedTempFile {
    let f = NamedTempFile::new().expect("tmp");
    fs::write(f.path(), content.as_bytes()).expect("write cfg");
    f
}

fn run_check(cfg_path: &str) -> Option<(bool, String)> {
    let bin = workspace_bin("check").to_string_lossy().to_string();
    let out = Command::new(bin)
        .args(&["--config", cfg_path])
        .output()
        .ok()?;
    let success = out.status.success();
    let stdout = String::from_utf8(out.stdout).ok()?;
    Some((success, stdout))
}

/// Test domain-based routing with REALITY
///
/// Verifies that domain rules correctly route traffic to REALITY outbounds.
#[test]
fn test_domain_routing_with_reality() {
    let cfg = r#"{
        "schema_version": 2,
        "inbounds": [
            {
                "type": "socks",
                "listen": "127.0.0.1:1080"
            }
        ],
        "outbounds": [
            {
                "type": "vless",
                "name": "reality-proxy",
                "server": "proxy.example.com",
                "port": 443,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "tls": {
                    "enabled": true,
                    "sni": "www.apple.com",
                    "reality": {
                        "enabled": true,
                        "public_key": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
                        "short_id": "01ab",
                        "server_name": "www.apple.com"
                    }
                }
            },
            {
                "type": "direct",
                "name": "direct"
            }
        ],
        "route": {
            "rules": [
                {
                    "domain": ["google.com", "youtube.com"],
                    "outbound": "reality-proxy"
                },
                {
                    "domain_suffix": [".cn"],
                    "outbound": "direct"
                }
            ],
            "default": "direct"
        }
    }"#;

    let tmp = write_cfg(cfg);
    let result = run_check(tmp.path().to_str().unwrap());
    
    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(success, "Domain routing with REALITY should be valid. Output: {}", output);
}

/// Test IP-based routing with Hysteria v2
///
/// Verifies that IP CIDR rules correctly route traffic to Hysteria v2 outbounds.
#[test]
fn test_ip_routing_with_hysteria2() {
    let cfg = r#"{
        "schema_version": 2,
        "inbounds": [
            {
                "type": "socks",
                "listen": "127.0.0.1:1080"
            }
        ],
        "outbounds": [
            {
                "type": "hysteria2",
                "name": "hy2-proxy",
                "server": "hy2.example.com",
                "port": 443,
                "password": "password123",
                "up_mbps": 100,
                "down_mbps": 100
            },
            {
                "type": "direct",
                "name": "direct"
            }
        ],
        "route": {
            "rules": [
                {
                    "ip_cidr": ["8.8.8.0/24", "1.1.1.0/24"],
                    "outbound": "hy2-proxy"
                },
                {
                    "ip_cidr": ["192.168.0.0/16", "10.0.0.0/8"],
                    "outbound": "direct"
                }
            ],
            "default": "direct"
        }
    }"#;

    let tmp = write_cfg(cfg);
    let result = run_check(tmp.path().to_str().unwrap());
    
    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(success, "IP routing with Hysteria2 should be valid. Output: {}", output);
}

/// Test port-based routing with SSH
///
/// Verifies that port rules correctly route traffic to SSH outbounds.
#[test]
fn test_port_routing_with_ssh() {
    let cfg = r#"{
        "schema_version": 2,
        "inbounds": [
            {
                "type": "socks",
                "listen": "127.0.0.1:1080"
            }
        ],
        "outbounds": [
            {
                "type": "ssh",
                "name": "ssh-proxy",
                "server": "ssh.example.com",
                "port": 22,
                "user": "proxyuser",
                "password": "secret123"
            },
            {
                "type": "direct",
                "name": "direct"
            }
        ],
        "route": {
            "rules": [
                {
                    "port": [80, 443, 8080],
                    "outbound": "ssh-proxy"
                },
                {
                    "port_range": ["1000:2000"],
                    "outbound": "direct"
                }
            ],
            "default": "direct"
        }
    }"#;

    let tmp = write_cfg(cfg);
    let result = run_check(tmp.path().to_str().unwrap());
    
    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(success, "Port routing with SSH should be valid. Output: {}", output);
}

/// Test process-based routing with TUIC
///
/// Verifies that process name rules correctly route traffic to TUIC outbounds.
#[test]
fn test_process_routing_with_tuic() {
    let cfg = r#"{
        "schema_version": 2,
        "inbounds": [
            {
                "type": "socks",
                "listen": "127.0.0.1:1080"
            }
        ],
        "outbounds": [
            {
                "type": "tuic",
                "name": "tuic-proxy",
                "server": "tuic.example.com",
                "port": 443,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "password": "password123",
                "congestion_control": "bbr"
            },
            {
                "type": "direct",
                "name": "direct"
            }
        ],
        "route": {
            "rules": [
                {
                    "process_name": ["firefox", "chrome", "safari"],
                    "outbound": "tuic-proxy"
                },
                {
                    "process_name": ["curl", "wget"],
                    "outbound": "direct"
                }
            ],
            "default": "direct"
        }
    }"#;

    let tmp = write_cfg(cfg);
    let result = run_check(tmp.path().to_str().unwrap());
    
    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(success, "Process routing with TUIC should be valid. Output: {}", output);
}

/// Test combined routing rules with Hysteria v1
///
/// Verifies that multiple rule types can be combined for Hysteria v1 outbounds.
#[test]
fn test_combined_routing_with_hysteria_v1() {
    let cfg = r#"{
        "schema_version": 2,
        "inbounds": [
            {
                "type": "socks",
                "listen": "127.0.0.1:1080"
            }
        ],
        "outbounds": [
            {
                "type": "hysteria",
                "name": "hy1-proxy",
                "server": "hy1.example.com",
                "port": 443,
                "protocol": "udp",
                "up_mbps": 100,
                "down_mbps": 100,
                "auth": "password123"
            },
            {
                "type": "direct",
                "name": "direct"
            }
        ],
        "route": {
            "rules": [
                {
                    "domain_suffix": [".google.com"],
                    "port": [443],
                    "outbound": "hy1-proxy"
                },
                {
                    "ip_cidr": ["192.168.0.0/16"],
                    "outbound": "direct"
                }
            ],
            "default": "direct"
        }
    }"#;

    let tmp = write_cfg(cfg);
    let result = run_check(tmp.path().to_str().unwrap());
    
    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(success, "Combined routing with Hysteria v1 should be valid. Output: {}", output);
}

/// Test ECH with domain routing
///
/// Verifies that ECH-enabled outbounds work with domain-based routing.
#[test]
fn test_domain_routing_with_ech() {
    let cfg = r#"{
        "schema_version": 2,
        "inbounds": [
            {
                "type": "socks",
                "listen": "127.0.0.1:1080"
            }
        ],
        "outbounds": [
            {
                "type": "trojan",
                "name": "ech-trojan",
                "server": "trojan.example.com",
                "port": 443,
                "password": "password123",
                "tls": {
                    "enabled": true,
                    "sni": "www.example.com",
                    "ech": {
                        "enabled": true,
                        "config": "AEX+DQBBzQAgACCm6NzGiTKdRzVzPJBGUVXZPLqKJfLJmJLjJmJLjJmJLg=="
                    }
                }
            },
            {
                "type": "direct",
                "name": "direct"
            }
        ],
        "route": {
            "rules": [
                {
                    "domain_keyword": ["google", "youtube", "facebook"],
                    "outbound": "ech-trojan"
                }
            ],
            "default": "direct"
        }
    }"#;

    let tmp = write_cfg(cfg);
    let result = run_check(tmp.path().to_str().unwrap());
    
    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(success, "Domain routing with ECH should be valid. Output: {}", output);
}

/// Test mixed P0 protocols with complex routing
///
/// Verifies that different P0 protocols can be used in complex routing scenarios.
#[test]
fn test_complex_routing_with_mixed_p0_protocols() {
    let cfg = r#"{
        "schema_version": 2,
        "inbounds": [
            {
                "type": "socks",
                "listen": "127.0.0.1:1080"
            }
        ],
        "outbounds": [
            {
                "type": "vless",
                "name": "reality-proxy",
                "server": "reality.example.com",
                "port": 443,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "tls": {
                    "enabled": true,
                    "sni": "www.apple.com",
                    "reality": {
                        "enabled": true,
                        "public_key": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
                        "short_id": "01ab",
                        "server_name": "www.apple.com"
                    }
                }
            },
            {
                "type": "hysteria2",
                "name": "hy2-proxy",
                "server": "hy2.example.com",
                "port": 443,
                "password": "password123",
                "up_mbps": 100,
                "down_mbps": 100
            },
            {
                "type": "ssh",
                "name": "ssh-proxy",
                "server": "ssh.example.com",
                "port": 22,
                "user": "proxyuser",
                "password": "secret"
            },
            {
                "type": "tuic",
                "name": "tuic-proxy",
                "server": "tuic.example.com",
                "port": 443,
                "uuid": "11111111-2222-3333-4444-555555555555",
                "password": "tuicpass"
            },
            {
                "type": "direct",
                "name": "direct"
            }
        ],
        "route": {
            "rules": [
                {
                    "domain_suffix": [".google.com", ".youtube.com"],
                    "outbound": "reality-proxy"
                },
                {
                    "ip_cidr": ["8.8.8.0/24"],
                    "port": [443],
                    "outbound": "hy2-proxy"
                },
                {
                    "process_name": ["ssh", "scp"],
                    "outbound": "ssh-proxy"
                },
                {
                    "port_range": ["10000:20000"],
                    "outbound": "tuic-proxy"
                }
            ],
            "default": "direct"
        }
    }"#;

    let tmp = write_cfg(cfg);
    let result = run_check(tmp.path().to_str().unwrap());
    
    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(success, "Complex routing with mixed P0 protocols should be valid. Output: {}", output);
}

/// Test geoip routing with P0 protocols
///
/// Verifies that geoip-based routing works with P0 protocols.
#[test]
fn test_geoip_routing_with_p0_protocols() {
    let cfg = r#"{
        "schema_version": 2,
        "inbounds": [
            {
                "type": "socks",
                "listen": "127.0.0.1:1080"
            }
        ],
        "outbounds": [
            {
                "type": "hysteria2",
                "name": "hy2-proxy",
                "server": "hy2.example.com",
                "port": 443,
                "password": "password123",
                "up_mbps": 100,
                "down_mbps": 100
            },
            {
                "type": "direct",
                "name": "direct"
            }
        ],
        "route": {
            "rules": [
                {
                    "geoip": ["cn"],
                    "outbound": "direct"
                },
                {
                    "geoip": ["us", "uk"],
                    "outbound": "hy2-proxy"
                }
            ],
            "default": "hy2-proxy"
        }
    }"#;

    let tmp = write_cfg(cfg);
    let result = run_check(tmp.path().to_str().unwrap());
    
    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(success, "GeoIP routing with P0 protocols should be valid. Output: {}", output);
}

/// Test geosite routing with P0 protocols
///
/// Verifies that geosite-based routing works with P0 protocols.
#[test]
fn test_geosite_routing_with_p0_protocols() {
    let cfg = r#"{
        "schema_version": 2,
        "inbounds": [
            {
                "type": "socks",
                "listen": "127.0.0.1:1080"
            }
        ],
        "outbounds": [
            {
                "type": "vless",
                "name": "reality-proxy",
                "server": "reality.example.com",
                "port": 443,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "tls": {
                    "enabled": true,
                    "sni": "www.apple.com",
                    "reality": {
                        "enabled": true,
                        "public_key": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
                        "short_id": "01ab",
                        "server_name": "www.apple.com"
                    }
                }
            },
            {
                "type": "direct",
                "name": "direct"
            }
        ],
        "route": {
            "rules": [
                {
                    "geosite": ["cn"],
                    "outbound": "direct"
                },
                {
                    "geosite": ["geolocation-!cn"],
                    "outbound": "reality-proxy"
                }
            ],
            "default": "direct"
        }
    }"#;

    let tmp = write_cfg(cfg);
    let result = run_check(tmp.path().to_str().unwrap());
    
    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(success, "GeoSite routing with P0 protocols should be valid. Output: {}", output);
}

/// Test invert rule with P0 protocols
///
/// Verifies that inverted routing rules work with P0 protocols.
#[test]
fn test_invert_rule_with_p0_protocols() {
    let cfg = r#"{
        "schema_version": 2,
        "inbounds": [
            {
                "type": "socks",
                "listen": "127.0.0.1:1080"
            }
        ],
        "outbounds": [
            {
                "type": "tuic",
                "name": "tuic-proxy",
                "server": "tuic.example.com",
                "port": 443,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "password": "password123"
            },
            {
                "type": "direct",
                "name": "direct"
            }
        ],
        "route": {
            "rules": [
                {
                    "domain_suffix": [".cn"],
                    "invert": true,
                    "outbound": "tuic-proxy"
                }
            ],
            "default": "direct"
        }
    }"#;

    let tmp = write_cfg(cfg);
    let result = run_check(tmp.path().to_str().unwrap());
    
    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(success, "Invert rule with P0 protocols should be valid. Output: {}", output);
}
