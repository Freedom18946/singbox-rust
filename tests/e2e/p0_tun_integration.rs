//! P0 Protocol Integration Tests with TUN Inbound
//!
//! Tests P0 protocols (REALITY, ECH, Hysteria v1/v2, SSH, TUIC) with:
//! - TUN → P0 protocol proxy chains
//! - UDP relay through TUN with Hysteria/TUIC
//! - Routing from TUN to P0 outbounds
//!
//! Requirements: 10.4

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

/// Test TUN inbound with REALITY outbound
///
/// Verifies that TUN device traffic can be routed through REALITY outbound.
#[test]
fn test_tun_to_reality() {
    let cfg = r#"{
        "schema_version": 2,
        "inbounds": [
            {
                "type": "tun",
                "interface_name": "tun0",
                "inet4_address": "172.19.0.1/30",
                "auto_route": true,
                "stack": "system"
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
            "rules": [],
            "default": "reality-proxy"
        }
    }"#;

    let tmp = write_cfg(cfg);
    let result = run_check(tmp.path().to_str().unwrap());
    
    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(success, "TUN to REALITY should be valid. Output: {}", output);
}

/// Test TUN inbound with Hysteria v2 outbound
///
/// Verifies that TUN device traffic can be routed through Hysteria v2 outbound.
#[test]
fn test_tun_to_hysteria2() {
    let cfg = r#"{
        "schema_version": 2,
        "inbounds": [
            {
                "type": "tun",
                "interface_name": "tun0",
                "inet4_address": "172.19.0.1/30",
                "auto_route": true,
                "stack": "gvisor"
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
            "rules": [],
            "default": "hy2-proxy"
        }
    }"#;

    let tmp = write_cfg(cfg);
    let result = run_check(tmp.path().to_str().unwrap());
    
    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(success, "TUN to Hysteria2 should be valid. Output: {}", output);
}

/// Test TUN UDP relay with Hysteria v2
///
/// Verifies that UDP traffic from TUN can be relayed through Hysteria v2.
#[test]
fn test_tun_udp_relay_with_hysteria2() {
    let cfg = r#"{
        "schema_version": 2,
        "inbounds": [
            {
                "type": "tun",
                "interface_name": "tun0",
                "inet4_address": "172.19.0.1/30",
                "auto_route": true,
                "stack": "gvisor",
                "udp_timeout": "5m"
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
                    "protocol": ["udp"],
                    "outbound": "hy2-proxy"
                }
            ],
            "default": "direct"
        }
    }"#;

    let tmp = write_cfg(cfg);
    let result = run_check(tmp.path().to_str().unwrap());
    
    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(success, "TUN UDP relay with Hysteria2 should be valid. Output: {}", output);
}

/// Test TUN UDP relay with TUIC
///
/// Verifies that UDP traffic from TUN can be relayed through TUIC.
#[test]
fn test_tun_udp_relay_with_tuic() {
    let cfg = r#"{
        "schema_version": 2,
        "inbounds": [
            {
                "type": "tun",
                "interface_name": "tun0",
                "inet4_address": "172.19.0.1/30",
                "auto_route": true,
                "stack": "gvisor",
                "udp_timeout": "5m"
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
                "congestion_control": "bbr",
                "udp_relay_mode": "native"
            },
            {
                "type": "direct",
                "name": "direct"
            }
        ],
        "route": {
            "rules": [
                {
                    "protocol": ["udp"],
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
    assert!(success, "TUN UDP relay with TUIC should be valid. Output: {}", output);
}

/// Test TUN with SSH outbound
///
/// Verifies that TUN device traffic can be routed through SSH outbound.
#[test]
fn test_tun_to_ssh() {
    let cfg = r#"{
        "schema_version": 2,
        "inbounds": [
            {
                "type": "tun",
                "interface_name": "tun0",
                "inet4_address": "172.19.0.1/30",
                "auto_route": true,
                "stack": "system"
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
            "rules": [],
            "default": "ssh-proxy"
        }
    }"#;

    let tmp = write_cfg(cfg);
    let result = run_check(tmp.path().to_str().unwrap());
    
    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(success, "TUN to SSH should be valid. Output: {}", output);
}

/// Test TUN with TUIC outbound
///
/// Verifies that TUN device traffic can be routed through TUIC outbound.
#[test]
fn test_tun_to_tuic() {
    let cfg = r#"{
        "schema_version": 2,
        "inbounds": [
            {
                "type": "tun",
                "interface_name": "tun0",
                "inet4_address": "172.19.0.1/30",
                "auto_route": true,
                "stack": "gvisor"
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
            "rules": [],
            "default": "tuic-proxy"
        }
    }"#;

    let tmp = write_cfg(cfg);
    let result = run_check(tmp.path().to_str().unwrap());
    
    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(success, "TUN to TUIC should be valid. Output: {}", output);
}

/// Test TUN with ECH-enabled outbound
///
/// Verifies that TUN device traffic can be routed through ECH-enabled outbound.
#[test]
fn test_tun_to_ech() {
    let cfg = r#"{
        "schema_version": 2,
        "inbounds": [
            {
                "type": "tun",
                "interface_name": "tun0",
                "inet4_address": "172.19.0.1/30",
                "auto_route": true,
                "stack": "system"
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
            "rules": [],
            "default": "ech-trojan"
        }
    }"#;

    let tmp = write_cfg(cfg);
    let result = run_check(tmp.path().to_str().unwrap());
    
    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(success, "TUN to ECH should be valid. Output: {}", output);
}

/// Test TUN with Hysteria v1 outbound
///
/// Verifies that TUN device traffic can be routed through Hysteria v1 outbound.
#[test]
fn test_tun_to_hysteria_v1() {
    let cfg = r#"{
        "schema_version": 2,
        "inbounds": [
            {
                "type": "tun",
                "interface_name": "tun0",
                "inet4_address": "172.19.0.1/30",
                "auto_route": true,
                "stack": "gvisor"
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
            "rules": [],
            "default": "hy1-proxy"
        }
    }"#;

    let tmp = write_cfg(cfg);
    let result = run_check(tmp.path().to_str().unwrap());
    
    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(success, "TUN to Hysteria v1 should be valid. Output: {}", output);
}

/// Test TUN with routing rules to P0 protocols
///
/// Verifies that TUN traffic can be routed to different P0 protocols based on rules.
#[test]
fn test_tun_routing_to_p0_protocols() {
    let cfg = r#"{
        "schema_version": 2,
        "inbounds": [
            {
                "type": "tun",
                "interface_name": "tun0",
                "inet4_address": "172.19.0.1/30",
                "auto_route": true,
                "stack": "gvisor"
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
                "type": "direct",
                "name": "direct"
            }
        ],
        "route": {
            "rules": [
                {
                    "domain_suffix": [".google.com"],
                    "outbound": "reality-proxy"
                },
                {
                    "protocol": ["udp"],
                    "port": [53],
                    "outbound": "hy2-proxy"
                },
                {
                    "port": [22],
                    "outbound": "ssh-proxy"
                }
            ],
            "default": "direct"
        }
    }"#;

    let tmp = write_cfg(cfg);
    let result = run_check(tmp.path().to_str().unwrap());
    
    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(success, "TUN routing to P0 protocols should be valid. Output: {}", output);
}

/// Test TUN with DNS and P0 protocols
///
/// Verifies that TUN with DNS configuration works with P0 protocols.
#[test]
fn test_tun_with_dns_and_p0_protocols() {
    let cfg = r#"{
        "schema_version": 2,
        "inbounds": [
            {
                "type": "tun",
                "interface_name": "tun0",
                "inet4_address": "172.19.0.1/30",
                "auto_route": true,
                "stack": "gvisor"
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
        "dns": {
            "servers": [
                {
                    "address": "8.8.8.8",
                    "detour": "hy2-proxy"
                }
            ]
        },
        "route": {
            "rules": [],
            "default": "hy2-proxy"
        }
    }"#;

    let tmp = write_cfg(cfg);
    let result = run_check(tmp.path().to_str().unwrap());
    
    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(success, "TUN with DNS and P0 protocols should be valid. Output: {}", output);
}

/// Test TUN with mixed stack and P0 protocols
///
/// Verifies that different TUN stack implementations work with P0 protocols.
#[test]
fn test_tun_mixed_stack_with_p0_protocols() {
    let cfg = r#"{
        "schema_version": 2,
        "inbounds": [
            {
                "type": "tun",
                "interface_name": "tun0",
                "inet4_address": "172.19.0.1/30",
                "inet6_address": "fdfe:dcba:9876::1/126",
                "auto_route": true,
                "stack": "mixed"
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
            "rules": [],
            "default": "tuic-proxy"
        }
    }"#;

    let tmp = write_cfg(cfg);
    let result = run_check(tmp.path().to_str().unwrap());
    
    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(success, "TUN mixed stack with P0 protocols should be valid. Output: {}", output);
}
