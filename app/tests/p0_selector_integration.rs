//! P0 Protocol Integration Tests with Selectors
//!
//! Tests P0 protocols (REALITY, ECH, Hysteria v1/v2, SSH, TUIC) with:
//! - URLTest selector (automatic health checking)
//! - Fallback selector (failover behavior)
//! - Manual selector (user selection)
//!
//! Requirements: 10.1

mod common;

use common::workspace::{run_check, write_temp_config};

/// Test REALITY TLS with URLTest selector
///
/// Verifies that REALITY outbounds can be used in a URLTest selector
/// for automatic health checking and failover.
#[test]
fn test_reality_with_urltest_selector() {
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
                "name": "reality-1",
                "server": "server1.example.com",
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
                "type": "vless",
                "name": "reality-2",
                "server": "server2.example.com",
                "port": 443,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "tls": {
                    "enabled": true,
                    "sni": "www.google.com",
                    "reality": {
                        "enabled": true,
                        "public_key": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                        "short_id": "02cd",
                        "server_name": "www.google.com"
                    }
                }
            },
            {
                "type": "urltest",
                "name": "auto-select",
                "outbounds": ["reality-1", "reality-2"],
                "url": "https://www.gstatic.com/generate_204",
                "interval": "5m"
            },
            {
                "type": "direct",
                "name": "direct"
            }
        ],
        "route": {
            "rules": [],
            "default": "auto-select"
        }
    }"#;

    let tmp = write_temp_config(cfg);
    let result = run_check(tmp.path().to_str().unwrap());

    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(
        success,
        "REALITY with URLTest selector should be valid. Output: {}",
        output
    );
}

/// Test Hysteria v2 with fallback selector
///
/// Verifies that Hysteria v2 outbounds can be used in a fallback selector
/// for automatic failover when primary fails.
#[test]
fn test_hysteria2_with_fallback_selector() {
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
                "name": "hy2-primary",
                "server": "primary.example.com",
                "port": 443,
                "password": "password123",
                "up_mbps": 100,
                "down_mbps": 100
            },
            {
                "type": "hysteria2",
                "name": "hy2-backup",
                "server": "backup.example.com",
                "port": 443,
                "password": "password456",
                "up_mbps": 50,
                "down_mbps": 50
            },
            {
                "type": "selector",
                "name": "fallback-group",
                "outbounds": ["hy2-primary", "hy2-backup"],
                "default": "hy2-primary"
            },
            {
                "type": "direct",
                "name": "direct"
            }
        ],
        "route": {
            "rules": [],
            "default": "fallback-group"
        }
    }"#;

    let tmp = write_temp_config(cfg);
    let result = run_check(tmp.path().to_str().unwrap());

    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(
        success,
        "Hysteria2 with fallback selector should be valid. Output: {}",
        output
    );
}

/// Test SSH with manual selector
///
/// Verifies that SSH outbounds can be used in a manual selector
/// for user-controlled proxy selection.
#[test]
fn test_ssh_with_manual_selector() {
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
                "name": "ssh-us",
                "server": "us.example.com",
                "port": 22,
                "user": "proxyuser",
                "password": "secret123"
            },
            {
                "type": "ssh",
                "name": "ssh-eu",
                "server": "eu.example.com",
                "port": 22,
                "user": "proxyuser",
                "password": "secret456"
            },
            {
                "type": "selector",
                "name": "manual-select",
                "outbounds": ["ssh-us", "ssh-eu"],
                "default": "ssh-us"
            },
            {
                "type": "direct",
                "name": "direct"
            }
        ],
        "route": {
            "rules": [],
            "default": "manual-select"
        }
    }"#;

    let tmp = write_temp_config(cfg);
    let result = run_check(tmp.path().to_str().unwrap());

    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(
        success,
        "SSH with manual selector should be valid. Output: {}",
        output
    );
}

/// Test TUIC with URLTest selector
///
/// Verifies that TUIC outbounds can be used in a URLTest selector
/// for automatic health checking.
#[test]
fn test_tuic_with_urltest_selector() {
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
                "name": "tuic-1",
                "server": "server1.example.com",
                "port": 443,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "password": "password123",
                "congestion_control": "bbr"
            },
            {
                "type": "tuic",
                "name": "tuic-2",
                "server": "server2.example.com",
                "port": 443,
                "uuid": "87654321-4321-4321-4321-cba987654321",
                "password": "password456",
                "congestion_control": "cubic"
            },
            {
                "type": "urltest",
                "name": "tuic-auto",
                "outbounds": ["tuic-1", "tuic-2"],
                "url": "https://www.gstatic.com/generate_204",
                "interval": "3m"
            },
            {
                "type": "direct",
                "name": "direct"
            }
        ],
        "route": {
            "rules": [],
            "default": "tuic-auto"
        }
    }"#;

    let tmp = write_temp_config(cfg);
    let result = run_check(tmp.path().to_str().unwrap());

    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(
        success,
        "TUIC with URLTest selector should be valid. Output: {}",
        output
    );
}

/// Test mixed P0 protocols in single URLTest selector
///
/// Verifies that different P0 protocols can coexist in the same selector
/// for comprehensive failover scenarios.
#[test]
fn test_mixed_p0_protocols_in_urltest() {
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
                "type": "urltest",
                "name": "best-proxy",
                "outbounds": ["reality-proxy", "hy2-proxy", "ssh-proxy", "tuic-proxy"],
                "url": "https://www.gstatic.com/generate_204",
                "interval": "5m",
                "tolerance": 50
            },
            {
                "type": "direct",
                "name": "direct"
            }
        ],
        "route": {
            "rules": [],
            "default": "best-proxy"
        }
    }"#;

    let tmp = write_temp_config(cfg);
    let result = run_check(tmp.path().to_str().unwrap());

    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(
        success,
        "Mixed P0 protocols in URLTest should be valid. Output: {}",
        output
    );
}

/// Test Hysteria v1 with selector
///
/// Verifies that Hysteria v1 outbounds work with selectors.
#[test]
fn test_hysteria_v1_with_selector() {
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
                "name": "hy1-1",
                "server": "hy1-server1.example.com",
                "port": 443,
                "protocol": "udp",
                "up_mbps": 100,
                "down_mbps": 100,
                "auth": "password123"
            },
            {
                "type": "hysteria",
                "name": "hy1-2",
                "server": "hy1-server2.example.com",
                "port": 443,
                "protocol": "udp",
                "up_mbps": 50,
                "down_mbps": 50,
                "auth": "password456"
            },
            {
                "type": "selector",
                "name": "hy1-group",
                "outbounds": ["hy1-1", "hy1-2"],
                "default": "hy1-1"
            },
            {
                "type": "direct",
                "name": "direct"
            }
        ],
        "route": {
            "rules": [],
            "default": "hy1-group"
        }
    }"#;

    let tmp = write_temp_config(cfg);
    let result = run_check(tmp.path().to_str().unwrap());

    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(
        success,
        "Hysteria v1 with selector should be valid. Output: {}",
        output
    );
}

/// Test ECH-enabled outbound with selector
///
/// Verifies that ECH-enabled TLS outbounds work with selectors.
#[test]
fn test_ech_with_selector() {
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
                "name": "ech-trojan-1",
                "server": "server1.example.com",
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
                "type": "trojan",
                "name": "ech-trojan-2",
                "server": "server2.example.com",
                "port": 443,
                "password": "password456",
                "tls": {
                    "enabled": true,
                    "sni": "www.example.org",
                    "ech": {
                        "enabled": true,
                        "config": "AEX+DQBBzQAgACCm6NzGiTKdRzVzPJBGUVXZPLqKJfLJmJLjJmJLjJmJLg=="
                    }
                }
            },
            {
                "type": "urltest",
                "name": "ech-auto",
                "outbounds": ["ech-trojan-1", "ech-trojan-2"],
                "url": "https://www.gstatic.com/generate_204",
                "interval": "5m"
            },
            {
                "type": "direct",
                "name": "direct"
            }
        ],
        "route": {
            "rules": [],
            "default": "ech-auto"
        }
    }"#;

    let tmp = write_temp_config(cfg);
    let result = run_check(tmp.path().to_str().unwrap());

    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(
        success,
        "ECH with selector should be valid. Output: {}",
        output
    );
}

/// Test nested selectors with P0 protocols
///
/// Verifies that P0 protocols work in nested selector configurations
/// (selector → selector → protocol).
#[test]
fn test_nested_selectors_with_p0_protocols() {
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
                "name": "hy2-us-1",
                "server": "us1.example.com",
                "port": 443,
                "password": "pass1",
                "up_mbps": 100,
                "down_mbps": 100
            },
            {
                "type": "hysteria2",
                "name": "hy2-us-2",
                "server": "us2.example.com",
                "port": 443,
                "password": "pass2",
                "up_mbps": 100,
                "down_mbps": 100
            },
            {
                "type": "tuic",
                "name": "tuic-eu-1",
                "server": "eu1.example.com",
                "port": 443,
                "uuid": "11111111-1111-1111-1111-111111111111",
                "password": "eupass1"
            },
            {
                "type": "tuic",
                "name": "tuic-eu-2",
                "server": "eu2.example.com",
                "port": 443,
                "uuid": "22222222-2222-2222-2222-222222222222",
                "password": "eupass2"
            },
            {
                "type": "urltest",
                "name": "us-group",
                "outbounds": ["hy2-us-1", "hy2-us-2"],
                "url": "https://www.gstatic.com/generate_204",
                "interval": "5m"
            },
            {
                "type": "urltest",
                "name": "eu-group",
                "outbounds": ["tuic-eu-1", "tuic-eu-2"],
                "url": "https://www.gstatic.com/generate_204",
                "interval": "5m"
            },
            {
                "type": "selector",
                "name": "region-select",
                "outbounds": ["us-group", "eu-group"],
                "default": "us-group"
            },
            {
                "type": "direct",
                "name": "direct"
            }
        ],
        "route": {
            "rules": [],
            "default": "region-select"
        }
    }"#;

    let tmp = write_temp_config(cfg);
    let result = run_check(tmp.path().to_str().unwrap());

    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(
        success,
        "Nested selectors with P0 protocols should be valid. Output: {}",
        output
    );
}

/// Test health check behavior with P0 protocols
///
/// Verifies that URLTest selector health check configuration works
/// with P0 protocols (interval, tolerance, timeout).
#[test]
fn test_health_check_config_with_p0_protocols() {
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
                "name": "reality-1",
                "server": "server1.example.com",
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
                "name": "hy2-1",
                "server": "hy2.example.com",
                "port": 443,
                "password": "password123",
                "up_mbps": 100,
                "down_mbps": 100
            },
            {
                "type": "urltest",
                "name": "health-checked",
                "outbounds": ["reality-1", "hy2-1"],
                "url": "https://www.gstatic.com/generate_204",
                "interval": "2m",
                "tolerance": 100,
                "timeout": "5s"
            },
            {
                "type": "direct",
                "name": "direct"
            }
        ],
        "route": {
            "rules": [],
            "default": "health-checked"
        }
    }"#;

    let tmp = write_temp_config(cfg);
    let result = run_check(tmp.path().to_str().unwrap());

    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(
        success,
        "Health check config with P0 protocols should be valid. Output: {}",
        output
    );
}
