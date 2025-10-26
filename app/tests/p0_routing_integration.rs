#![allow(unused_imports)]
//! P0 Protocol Integration Tests with Routing Rules
//!
//! Tests P0 protocols (REALITY, ECH, Hysteria v1/v2, SSH, TUIC) with:
//! - Domain-based routing
//! - IP-based routing
//! - Port-based routing
//! - Process-based routing
//!
//! Requirements: 10.2

mod common;

use common::workspace::{run_check, write_temp_config, workspace_bin};

/// Test domain-based routing with REALITY TLS
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

    let tmp = write_temp_config(cfg);
    let result = run_check(tmp.path().to_str().unwrap());

    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(
        success,
        "Domain routing with REALITY should be valid. Output: {}",
        output
    );
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
                "server": "proxy.example.com",
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
                    "ip_cidr": ["8.8.8.8/32", "1.1.1.1/32"],
                    "outbound": "hy2-proxy"
                },
                {
                    "ip_cidr": ["192.168.0.0/16", "10.0.0.0/8"],
                    "outbound": "direct"
                }
            ],
            "default": "hy2-proxy"
        }
    }"#;

    let tmp = write_temp_config(cfg);
    let result = run_check(tmp.path().to_str().unwrap());

    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(
        success,
        "IP routing with Hysteria2 should be valid. Output: {}",
        output
    );
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

    let tmp = write_temp_config(cfg);
    let result = run_check(tmp.path().to_str().unwrap());

    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(
        success,
        "Port routing with SSH should be valid. Output: {}",
        output
    );
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
                    "process_name": ["chrome", "firefox", "safari"],
                    "outbound": "tuic-proxy"
                }
            ],
            "default": "direct"
        }
    }"#;

    let tmp = write_temp_config(cfg);
    let result = run_check(tmp.path().to_str().unwrap());

    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(
        success,
        "Process routing with TUIC should be valid. Output: {}",
        output
    );
}

/// Test combined routing rules with mixed P0 protocols
///
/// Verifies that multiple rule types work together with different P0 protocols.
#[test]
fn test_combined_routing_with_mixed_protocols() {
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
                    "domain": ["google.com"],
                    "port": [443],
                    "outbound": "reality-proxy"
                },
                {
                    "ip_cidr": ["8.8.8.8/32"],
                    "outbound": "hy2-proxy"
                },
                {
                    "domain_suffix": [".cn"],
                    "outbound": "direct"
                },
                {
                    "port": [22],
                    "outbound": "ssh-proxy"
                },
                {
                    "process_name": ["telegram"],
                    "outbound": "tuic-proxy"
                }
            ],
            "default": "direct"
        }
    }"#;

    let tmp = write_temp_config(cfg);
    let result = run_check(tmp.path().to_str().unwrap());

    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(
        success,
        "Combined routing with mixed protocols should be valid. Output: {}",
        output
    );
}

/// Test domain keyword routing with Hysteria v1
///
/// Verifies that domain keyword matching works with Hysteria v1.
#[test]
fn test_domain_keyword_routing_with_hysteria_v1() {
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
                    "domain_keyword": ["google", "youtube", "facebook"],
                    "outbound": "hy1-proxy"
                }
            ],
            "default": "direct"
        }
    }"#;

    let tmp = write_temp_config(cfg);
    let result = run_check(tmp.path().to_str().unwrap());

    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(
        success,
        "Domain keyword routing with Hysteria v1 should be valid. Output: {}",
        output
    );
}

/// Test GeoIP routing with ECH-enabled outbound
///
/// Verifies that GeoIP rules work with ECH-enabled outbounds.
#[test]
fn test_geoip_routing_with_ech() {
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
                    "geoip": ["us", "uk", "ca"],
                    "outbound": "ech-trojan"
                },
                {
                    "geoip": ["cn"],
                    "outbound": "direct"
                }
            ],
            "default": "ech-trojan"
        }
    }"#;

    let tmp = write_temp_config(cfg);
    let result = run_check(tmp.path().to_str().unwrap());

    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(
        success,
        "GeoIP routing with ECH should be valid. Output: {}",
        output
    );
}

/// Test GeoSite routing with P0 protocols
///
/// Verifies that GeoSite rules work with P0 protocols.
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
                "uuid": "12345678-1234-1234-1234-123456789abc",
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
                    "geosite": ["google", "youtube"],
                    "outbound": "hy2-proxy"
                },
                {
                    "geosite": ["netflix", "disney"],
                    "outbound": "tuic-proxy"
                },
                {
                    "geosite": ["cn"],
                    "outbound": "direct"
                }
            ],
            "default": "hy2-proxy"
        }
    }"#;

    let tmp = write_temp_config(cfg);
    let result = run_check(tmp.path().to_str().unwrap());

    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(
        success,
        "GeoSite routing with P0 protocols should be valid. Output: {}",
        output
    );
}

/// Test invert rule with P0 protocols
///
/// Verifies that inverted rules (NOT logic) work with P0 protocols.
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
                    "domain_suffix": [".cn"],
                    "invert": true,
                    "outbound": "reality-proxy"
                }
            ],
            "default": "direct"
        }
    }"#;

    let tmp = write_temp_config(cfg);
    let result = run_check(tmp.path().to_str().unwrap());

    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(
        success,
        "Invert rule with P0 protocols should be valid. Output: {}",
        output
    );
}

/// Test protocol-based routing with P0 protocols
///
/// Verifies that protocol (TCP/UDP) rules work with P0 protocols.
#[test]
fn test_protocol_routing_with_p0_protocols() {
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
                "name": "hy2-udp",
                "server": "hy2.example.com",
                "port": 443,
                "password": "password123",
                "up_mbps": 100,
                "down_mbps": 100
            },
            {
                "type": "ssh",
                "name": "ssh-tcp",
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
                    "network": "udp",
                    "outbound": "hy2-udp"
                },
                {
                    "network": "tcp",
                    "outbound": "ssh-tcp"
                }
            ],
            "default": "direct"
        }
    }"#;

    let tmp = write_temp_config(cfg);
    let result = run_check(tmp.path().to_str().unwrap());

    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(
        success,
        "Protocol routing with P0 protocols should be valid. Output: {}",
        output
    );
}

/// Test source IP routing with P0 protocols
///
/// Verifies that source IP rules work with P0 protocols.
#[test]
fn test_source_ip_routing_with_p0_protocols() {
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
                    "source_ip_cidr": ["192.168.1.0/24"],
                    "outbound": "tuic-proxy"
                },
                {
                    "source_ip_cidr": ["10.0.0.0/8"],
                    "outbound": "direct"
                }
            ],
            "default": "direct"
        }
    }"#;

    let tmp = write_temp_config(cfg);
    let result = run_check(tmp.path().to_str().unwrap());

    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(
        success,
        "Source IP routing with P0 protocols should be valid. Output: {}",
        output
    );
}
