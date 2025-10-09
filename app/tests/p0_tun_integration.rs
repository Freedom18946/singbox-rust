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
/// Verifies that TUN traffic can be routed through REALITY outbounds.
#[test]
fn test_tun_with_reality_outbound() {
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
            "rules": [
                {
                    "domain": ["google.com"],
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
    assert!(success, "TUN with REALITY outbound should be valid. Output: {}", output);
}

/// Test TUN inbound with Hysteria v2 outbound
///
/// Verifies that TUN traffic (TCP and UDP) can be routed through Hysteria v2.
#[test]
fn test_tun_with_hysteria2_outbound() {
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
    assert!(success, "TUN with Hysteria2 outbound should be valid. Output: {}", output);
}

/// Test TUN inbound with SSH outbound
///
/// Verifies that TUN traffic can be tunneled through SSH.
#[test]
fn test_tun_with_ssh_outbound() {
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
    assert!(success, "TUN with SSH outbound should be valid. Output: {}", output);
}

/// Test TUN inbound with TUIC outbound
///
/// Verifies that TUN traffic (TCP and UDP) can be routed through TUIC.
#[test]
fn test_tun_with_tuic_outbound() {
    let cfg = r#"{
        "schema_version": 2,
        "inbounds": [
            {
                "type": "tun",
                "interface_name": "tun0",
                "inet4_address": "172.19.0.1/30",
                "inet6_address": "fdfe:dcba:9876::1/126",
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
                "password": "password123",
                "udp_relay_mode": "native"
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
    assert!(success, "TUN with TUIC outbound should be valid. Output: {}", output);
}

/// Test TUN UDP relay with Hysteria v1
///
/// Verifies that UDP traffic from TUN can be relayed through Hysteria v1.
#[test]
fn test_tun_udp_relay_with_hysteria_v1() {
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
            "rules": [
                {
                    "network": "udp",
                    "outbound": "hy1-proxy"
                }
            ],
            "default": "direct"
        }
    }"#;

    let tmp = write_cfg(cfg);
    let result = run_check(tmp.path().to_str().unwrap());
    
    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(success, "TUN UDP relay with Hysteria v1 should be valid. Output: {}", output);
}

/// Test TUN with ECH-enabled outbound
///
/// Verifies that TUN traffic can be routed through ECH-enabled outbounds.
#[test]
fn test_tun_with_ech_outbound() {
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
    assert!(success, "TUN with ECH outbound should be valid. Output: {}", output);
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
                    "domain": ["google.com", "youtube.com"],
                    "outbound": "reality-proxy"
                },
                {
                    "network": "udp",
                    "port": [53],
                    "outbound": "hy2-proxy"
                },
                {
                    "ip_cidr": ["8.8.8.8/32"],
                    "outbound": "tuic-proxy"
                },
                {
                    "domain_suffix": [".cn"],
                    "outbound": "direct"
                }
            ],
            "default": "reality-proxy"
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
/// Verifies that TUN DNS queries can be routed through P0 protocols.
#[test]
fn test_tun_dns_with_p0_protocols() {
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
                    "address": "https://dns.google/dns-query",
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
    assert!(success, "TUN DNS with P0 protocols should be valid. Output: {}", output);
}

/// Test TUN with Fake-IP and P0 protocols
///
/// Verifies that TUN with Fake-IP mode works with P0 protocols.
#[test]
fn test_tun_fakeip_with_p0_protocols() {
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
        "dns": {
            "servers": [
                {
                    "address": "fakeip"
                },
                {
                    "address": "8.8.8.8",
                    "detour": "tuic-proxy"
                }
            ],
            "fakeip": {
                "enabled": true,
                "inet4_range": "198.18.0.0/15",
                "inet6_range": "fc00::/18"
            }
        },
        "route": {
            "rules": [],
            "default": "tuic-proxy"
        }
    }"#;

    let tmp = write_cfg(cfg);
    let result = run_check(tmp.path().to_str().unwrap());
    
    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(success, "TUN Fake-IP with P0 protocols should be valid. Output: {}", output);
}

/// Test TUN with mixed stack and P0 protocols
///
/// Verifies that different TUN stacks (system, gvisor) work with P0 protocols.
#[test]
fn test_tun_mixed_stack_with_p0_protocols() {
    let cfg = r#"{
        "schema_version": 2,
        "inbounds": [
            {
                "type": "tun",
                "interface_name": "tun0",
                "inet4_address": "172.19.0.1/30",
                "auto_route": true,
                "stack": "mixed"
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
            "rules": [],
            "default": "reality-proxy"
        }
    }"#;

    let tmp = write_cfg(cfg);
    let result = run_check(tmp.path().to_str().unwrap());
    
    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(success, "TUN mixed stack with P0 protocols should be valid. Output: {}", output);
}

/// Test TUN with IPv6 and P0 protocols
///
/// Verifies that TUN IPv6 traffic works with P0 protocols.
#[test]
fn test_tun_ipv6_with_p0_protocols() {
    let cfg = r#"{
        "schema_version": 2,
        "inbounds": [
            {
                "type": "tun",
                "interface_name": "tun0",
                "inet4_address": "172.19.0.1/30",
                "inet6_address": "fdfe:dcba:9876::1/126",
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
    assert!(success, "TUN IPv6 with P0 protocols should be valid. Output: {}", output);
}
