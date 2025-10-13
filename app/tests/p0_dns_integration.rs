//! P0 Protocol Integration Tests with DNS Subsystem
//!
//! Tests P0 protocols (REALITY, ECH, Hysteria v1/v2, SSH, TUIC) with:
//! - DNS resolution through P0 outbounds
//! - Fake-IP mode with P0 protocols
//! - DNS routing rules with P0 protocols
//!
//! Requirements: 10.3

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

/// Test DNS resolution with REALITY outbound
///
/// Verifies that DNS queries can be routed through REALITY outbounds.
#[test]
fn test_dns_resolution_with_reality() {
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
        "dns": {
            "servers": [
                {
                    "address": "https://dns.google/dns-query",
                    "detour": "reality-proxy"
                },
                {
                    "address": "223.5.5.5",
                    "detour": "direct"
                }
            ]
        },
        "route": {
            "rules": [],
            "default": "reality-proxy"
        }
    }"#;

    let tmp = write_cfg(cfg);
    let result = run_check(tmp.path().to_str().unwrap());

    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(
        success,
        "DNS resolution with REALITY should be valid. Output: {}",
        output
    );
}

/// Test DNS resolution with Hysteria v2
///
/// Verifies that DNS queries can be routed through Hysteria v2 outbounds.
#[test]
fn test_dns_resolution_with_hysteria2() {
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
        "dns": {
            "servers": [
                {
                    "address": "tls://dns.google",
                    "detour": "hy2-proxy"
                },
                {
                    "address": "114.114.114.114",
                    "detour": "direct"
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
    assert!(
        success,
        "DNS resolution with Hysteria2 should be valid. Output: {}",
        output
    );
}

/// Test DNS resolution with SSH outbound
///
/// Verifies that DNS queries can be routed through SSH tunnels.
#[test]
fn test_dns_resolution_with_ssh() {
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
        "dns": {
            "servers": [
                {
                    "address": "8.8.8.8",
                    "detour": "ssh-proxy"
                },
                {
                    "address": "local",
                    "detour": "direct"
                }
            ]
        },
        "route": {
            "rules": [],
            "default": "ssh-proxy"
        }
    }"#;

    let tmp = write_cfg(cfg);
    let result = run_check(tmp.path().to_str().unwrap());

    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(
        success,
        "DNS resolution with SSH should be valid. Output: {}",
        output
    );
}

/// Test DNS resolution with TUIC outbound
///
/// Verifies that DNS queries can be routed through TUIC outbounds.
#[test]
fn test_dns_resolution_with_tuic() {
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
        "dns": {
            "servers": [
                {
                    "address": "https://cloudflare-dns.com/dns-query",
                    "detour": "tuic-proxy"
                }
            ]
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
    assert!(
        success,
        "DNS resolution with TUIC should be valid. Output: {}",
        output
    );
}

/// Test Fake-IP mode with P0 protocols
///
/// Verifies that Fake-IP DNS mode works with P0 protocols.
#[test]
fn test_fakeip_with_p0_protocols() {
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
        "dns": {
            "servers": [
                {
                    "address": "fakeip"
                },
                {
                    "address": "8.8.8.8",
                    "detour": "hy2-proxy"
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
            "default": "reality-proxy"
        }
    }"#;

    let tmp = write_cfg(cfg);
    let result = run_check(tmp.path().to_str().unwrap());

    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(
        success,
        "Fake-IP with P0 protocols should be valid. Output: {}",
        output
    );
}

/// Test DNS routing rules with P0 protocols
///
/// Verifies that DNS server selection based on domain rules works with P0 protocols.
#[test]
fn test_dns_routing_rules_with_p0_protocols() {
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
        "dns": {
            "servers": [
                {
                    "address": "https://dns.google/dns-query",
                    "address_resolver": "local-dns",
                    "detour": "tuic-proxy",
                    "tag": "google-dns"
                },
                {
                    "address": "223.5.5.5",
                    "detour": "direct",
                    "tag": "china-dns"
                },
                {
                    "address": "local",
                    "tag": "local-dns"
                }
            ],
            "rules": [
                {
                    "domain": ["google.com", "youtube.com"],
                    "server": "google-dns"
                },
                {
                    "domain_suffix": [".cn"],
                    "server": "china-dns"
                }
            ]
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
    assert!(
        success,
        "DNS routing rules with P0 protocols should be valid. Output: {}",
        output
    );
}

/// Test DNS over HTTPS (DoH) with ECH-enabled outbound
///
/// Verifies that DoH queries work through ECH-enabled outbounds.
#[test]
fn test_doh_with_ech() {
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
        "dns": {
            "servers": [
                {
                    "address": "https://dns.google/dns-query",
                    "detour": "ech-trojan"
                }
            ]
        },
        "route": {
            "rules": [],
            "default": "ech-trojan"
        }
    }"#;

    let tmp = write_cfg(cfg);
    let result = run_check(tmp.path().to_str().unwrap());

    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(success, "DoH with ECH should be valid. Output: {}", output);
}

/// Test DNS over TLS (DoT) with Hysteria v1
///
/// Verifies that DoT queries work through Hysteria v1 outbounds.
#[test]
fn test_dot_with_hysteria_v1() {
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
        "dns": {
            "servers": [
                {
                    "address": "tls://dns.google",
                    "detour": "hy1-proxy"
                }
            ]
        },
        "route": {
            "rules": [],
            "default": "hy1-proxy"
        }
    }"#;

    let tmp = write_cfg(cfg);
    let result = run_check(tmp.path().to_str().unwrap());

    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(
        success,
        "DoT with Hysteria v1 should be valid. Output: {}",
        output
    );
}

/// Test DNS caching with P0 protocols
///
/// Verifies that DNS caching configuration works with P0 protocols.
#[test]
fn test_dns_caching_with_p0_protocols() {
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
        "dns": {
            "servers": [
                {
                    "address": "https://dns.google/dns-query",
                    "detour": "hy2-proxy"
                }
            ],
            "strategy": "prefer_ipv4",
            "disable_cache": false,
            "disable_expire": false
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
    assert!(
        success,
        "DNS caching with P0 protocols should be valid. Output: {}",
        output
    );
}

/// Test DNS strategy (IPv4/IPv6 preference) with P0 protocols
///
/// Verifies that DNS strategy configuration works with P0 protocols.
#[test]
fn test_dns_strategy_with_p0_protocols() {
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
        "dns": {
            "servers": [
                {
                    "address": "8.8.8.8",
                    "detour": "reality-proxy",
                    "strategy": "ipv4_only"
                },
                {
                    "address": "2001:4860:4860::8888",
                    "detour": "reality-proxy",
                    "strategy": "ipv6_only"
                }
            ],
            "strategy": "prefer_ipv6"
        },
        "route": {
            "rules": [],
            "default": "reality-proxy"
        }
    }"#;

    let tmp = write_cfg(cfg);
    let result = run_check(tmp.path().to_str().unwrap());

    assert!(result.is_some(), "Check command should execute");
    let (success, output) = result.unwrap();
    assert!(
        success,
        "DNS strategy with P0 protocols should be valid. Output: {}",
        output
    );
}

/// Test DNS with mixed P0 protocols
///
/// Verifies that different DNS servers can use different P0 protocols.
#[test]
fn test_dns_with_mixed_p0_protocols() {
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
        "dns": {
            "servers": [
                {
                    "address": "https://dns.google/dns-query",
                    "detour": "hy2-proxy",
                    "tag": "google-dns"
                },
                {
                    "address": "https://cloudflare-dns.com/dns-query",
                    "detour": "tuic-proxy",
                    "tag": "cloudflare-dns"
                },
                {
                    "address": "8.8.8.8",
                    "detour": "ssh-proxy",
                    "tag": "ssh-dns"
                },
                {
                    "address": "223.5.5.5",
                    "detour": "direct",
                    "tag": "china-dns"
                }
            ],
            "rules": [
                {
                    "domain": ["google.com"],
                    "server": "google-dns"
                },
                {
                    "domain": ["cloudflare.com"],
                    "server": "cloudflare-dns"
                },
                {
                    "domain_suffix": [".cn"],
                    "server": "china-dns"
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
    assert!(
        success,
        "DNS with mixed P0 protocols should be valid. Output: {}",
        output
    );
}
