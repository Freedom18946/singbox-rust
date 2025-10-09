//! P0 Protocol Upstream Compatibility Tests
//!
//! Tests compatibility between Rust implementation and upstream Go sing-box for:
//! - Config file compatibility
//! - Protocol interoperability (Rust client ↔ Go server, Go client ↔ Rust server)
//! - Feature parity verification
//!
//! Requirements: 10.5, 8.5
//!
//! Note: These tests require upstream sing-box binary to be available.
//! Set GO_SINGBOX_BIN environment variable to the path of sing-box binary.

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

fn run_check(bin: &str, cfg_path: &str) -> Option<(bool, String)> {
    let out = Command::new(bin)
        .args(&["--config", cfg_path])
        .output()
        .ok()?;
    let success = out.status.success();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    Some((success, format!("{}\n{}", stdout, stderr)))
}

fn go_bin() -> Option<String> {
    std::env::var("GO_SINGBOX_BIN")
        .ok()
        .filter(|s| !s.is_empty())
}

/// Test REALITY config compatibility with upstream
///
/// Verifies that REALITY configs are accepted by both Rust and Go implementations.
#[test]
fn test_reality_config_compatibility() {
    let cfg = r#"{
        "log": {
            "level": "info"
        },
        "inbounds": [
            {
                "type": "socks",
                "listen": "127.0.0.1",
                "listen_port": 1080
            }
        ],
        "outbounds": [
            {
                "type": "vless",
                "tag": "reality-proxy",
                "server": "proxy.example.com",
                "server_port": 443,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "flow": "xtls-rprx-vision",
                "tls": {
                    "enabled": true,
                    "server_name": "www.apple.com",
                    "reality": {
                        "enabled": true,
                        "public_key": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
                        "short_id": "01ab"
                    }
                }
            },
            {
                "type": "direct",
                "tag": "direct"
            }
        ],
        "route": {
            "rules": [],
            "final": "reality-proxy"
        }
    }"#;

    let tmp = write_cfg(cfg);
    
    // Test Rust implementation
    let rust_bin = workspace_bin("check").to_string_lossy().to_string();
    let rust_result = run_check(&rust_bin, tmp.path().to_str().unwrap());
    assert!(rust_result.is_some(), "Rust check should execute");
    let (rust_success, rust_output) = rust_result.unwrap();
    
    // Test Go implementation if available
    if let Some(go_bin_path) = go_bin() {
        let go_result = run_check(&go_bin_path, tmp.path().to_str().unwrap());
        if let Some((go_success, go_output)) = go_result {
            println!("Rust result: {}", rust_success);
            println!("Go result: {}", go_success);
            println!("Rust output: {}", rust_output);
            println!("Go output: {}", go_output);
            
            // Both should accept or reject the config consistently
            assert_eq!(
                rust_success, go_success,
                "Rust and Go should have same validation result for REALITY config"
            );
        } else {
            println!("Go sing-box check failed to execute, skipping comparison");
        }
    } else {
        println!("GO_SINGBOX_BIN not set, skipping upstream comparison");
    }
    
    // At minimum, Rust implementation should accept valid config
    assert!(rust_success, "Rust should accept valid REALITY config. Output: {}", rust_output);
}

/// Test Hysteria v2 config compatibility with upstream
///
/// Verifies that Hysteria v2 configs are accepted by both implementations.
#[test]
fn test_hysteria2_config_compatibility() {
    let cfg = r#"{
        "log": {
            "level": "info"
        },
        "inbounds": [
            {
                "type": "socks",
                "listen": "127.0.0.1",
                "listen_port": 1080
            }
        ],
        "outbounds": [
            {
                "type": "hysteria2",
                "tag": "hy2-proxy",
                "server": "hy2.example.com",
                "server_port": 443,
                "password": "password123",
                "up_mbps": 100,
                "down_mbps": 100
            },
            {
                "type": "direct",
                "tag": "direct"
            }
        ],
        "route": {
            "rules": [],
            "final": "hy2-proxy"
        }
    }"#;

    let tmp = write_cfg(cfg);
    
    let rust_bin = workspace_bin("check").to_string_lossy().to_string();
    let rust_result = run_check(&rust_bin, tmp.path().to_str().unwrap());
    assert!(rust_result.is_some(), "Rust check should execute");
    let (rust_success, rust_output) = rust_result.unwrap();
    
    if let Some(go_bin_path) = go_bin() {
        let go_result = run_check(&go_bin_path, tmp.path().to_str().unwrap());
        if let Some((go_success, go_output)) = go_result {
            println!("Rust result: {}", rust_success);
            println!("Go result: {}", go_success);
            assert_eq!(
                rust_success, go_success,
                "Rust and Go should have same validation result for Hysteria2 config"
            );
        }
    }
    
    assert!(rust_success, "Rust should accept valid Hysteria2 config. Output: {}", rust_output);
}

/// Test SSH config compatibility with upstream
///
/// Verifies that SSH configs are accepted by both implementations.
#[test]
fn test_ssh_config_compatibility() {
    let cfg = r#"{
        "log": {
            "level": "info"
        },
        "inbounds": [
            {
                "type": "socks",
                "listen": "127.0.0.1",
                "listen_port": 1080
            }
        ],
        "outbounds": [
            {
                "type": "ssh",
                "tag": "ssh-proxy",
                "server": "ssh.example.com",
                "server_port": 22,
                "user": "proxyuser",
                "password": "secret123"
            },
            {
                "type": "direct",
                "tag": "direct"
            }
        ],
        "route": {
            "rules": [],
            "final": "ssh-proxy"
        }
    }"#;

    let tmp = write_cfg(cfg);
    
    let rust_bin = workspace_bin("check").to_string_lossy().to_string();
    let rust_result = run_check(&rust_bin, tmp.path().to_str().unwrap());
    assert!(rust_result.is_some(), "Rust check should execute");
    let (rust_success, rust_output) = rust_result.unwrap();
    
    if let Some(go_bin_path) = go_bin() {
        let go_result = run_check(&go_bin_path, tmp.path().to_str().unwrap());
        if let Some((go_success, go_output)) = go_result {
            println!("Rust result: {}", rust_success);
            println!("Go result: {}", go_success);
            assert_eq!(
                rust_success, go_success,
                "Rust and Go should have same validation result for SSH config"
            );
        }
    }
    
    assert!(rust_success, "Rust should accept valid SSH config. Output: {}", rust_output);
}

/// Test TUIC config compatibility with upstream
///
/// Verifies that TUIC configs are accepted by both implementations.
#[test]
fn test_tuic_config_compatibility() {
    let cfg = r#"{
        "log": {
            "level": "info"
        },
        "inbounds": [
            {
                "type": "socks",
                "listen": "127.0.0.1",
                "listen_port": 1080
            }
        ],
        "outbounds": [
            {
                "type": "tuic",
                "tag": "tuic-proxy",
                "server": "tuic.example.com",
                "server_port": 443,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "password": "password123",
                "congestion_control": "bbr"
            },
            {
                "type": "direct",
                "tag": "direct"
            }
        ],
        "route": {
            "rules": [],
            "final": "tuic-proxy"
        }
    }"#;

    let tmp = write_cfg(cfg);
    
    let rust_bin = workspace_bin("check").to_string_lossy().to_string();
    let rust_result = run_check(&rust_bin, tmp.path().to_str().unwrap());
    assert!(rust_result.is_some(), "Rust check should execute");
    let (rust_success, rust_output) = rust_result.unwrap();
    
    if let Some(go_bin_path) = go_bin() {
        let go_result = run_check(&go_bin_path, tmp.path().to_str().unwrap());
        if let Some((go_success, go_output)) = go_result {
            println!("Rust result: {}", rust_success);
            println!("Go result: {}", go_success);
            assert_eq!(
                rust_success, go_success,
                "Rust and Go should have same validation result for TUIC config"
            );
        }
    }
    
    assert!(rust_success, "Rust should accept valid TUIC config. Output: {}", rust_output);
}

/// Test ECH config compatibility with upstream
///
/// Verifies that ECH configs are accepted by both implementations.
#[test]
fn test_ech_config_compatibility() {
    let cfg = r#"{
        "log": {
            "level": "info"
        },
        "inbounds": [
            {
                "type": "socks",
                "listen": "127.0.0.1",
                "listen_port": 1080
            }
        ],
        "outbounds": [
            {
                "type": "trojan",
                "tag": "ech-trojan",
                "server": "trojan.example.com",
                "server_port": 443,
                "password": "password123",
                "tls": {
                    "enabled": true,
                    "server_name": "www.example.com",
                    "ech": {
                        "enabled": true,
                        "config": "AEX+DQBBzQAgACCm6NzGiTKdRzVzPJBGUVXZPLqKJfLJmJLjJmJLjJmJLg=="
                    }
                }
            },
            {
                "type": "direct",
                "tag": "direct"
            }
        ],
        "route": {
            "rules": [],
            "final": "ech-trojan"
        }
    }"#;

    let tmp = write_cfg(cfg);
    
    let rust_bin = workspace_bin("check").to_string_lossy().to_string();
    let rust_result = run_check(&rust_bin, tmp.path().to_str().unwrap());
    assert!(rust_result.is_some(), "Rust check should execute");
    let (rust_success, rust_output) = rust_result.unwrap();
    
    if let Some(go_bin_path) = go_bin() {
        let go_result = run_check(&go_bin_path, tmp.path().to_str().unwrap());
        if let Some((go_success, go_output)) = go_result {
            println!("Rust result: {}", rust_success);
            println!("Go result: {}", go_success);
            assert_eq!(
                rust_success, go_success,
                "Rust and Go should have same validation result for ECH config"
            );
        }
    }
    
    assert!(rust_success, "Rust should accept valid ECH config. Output: {}", rust_output);
}

/// Test Hysteria v1 config compatibility with upstream
///
/// Verifies that Hysteria v1 configs are accepted by both implementations.
#[test]
fn test_hysteria_v1_config_compatibility() {
    let cfg = r#"{
        "log": {
            "level": "info"
        },
        "inbounds": [
            {
                "type": "socks",
                "listen": "127.0.0.1",
                "listen_port": 1080
            }
        ],
        "outbounds": [
            {
                "type": "hysteria",
                "tag": "hy1-proxy",
                "server": "hy1.example.com",
                "server_port": 443,
                "protocol": "udp",
                "up_mbps": 100,
                "down_mbps": 100,
                "auth_str": "password123"
            },
            {
                "type": "direct",
                "tag": "direct"
            }
        ],
        "route": {
            "rules": [],
            "final": "hy1-proxy"
        }
    }"#;

    let tmp = write_cfg(cfg);
    
    let rust_bin = workspace_bin("check").to_string_lossy().to_string();
    let rust_result = run_check(&rust_bin, tmp.path().to_str().unwrap());
    assert!(rust_result.is_some(), "Rust check should execute");
    let (rust_success, rust_output) = rust_result.unwrap();
    
    if let Some(go_bin_path) = go_bin() {
        let go_result = run_check(&go_bin_path, tmp.path().to_str().unwrap());
        if let Some((go_success, go_output)) = go_result {
            println!("Rust result: {}", rust_success);
            println!("Go result: {}", go_success);
            assert_eq!(
                rust_success, go_success,
                "Rust and Go should have same validation result for Hysteria v1 config"
            );
        }
    }
    
    assert!(rust_success, "Rust should accept valid Hysteria v1 config. Output: {}", rust_output);
}

/// Test mixed P0 protocols config compatibility
///
/// Verifies that complex configs with multiple P0 protocols work in both implementations.
#[test]
fn test_mixed_p0_protocols_compatibility() {
    let cfg = r#"{
        "log": {
            "level": "info"
        },
        "inbounds": [
            {
                "type": "socks",
                "listen": "127.0.0.1",
                "listen_port": 1080
            }
        ],
        "outbounds": [
            {
                "type": "vless",
                "tag": "reality-proxy",
                "server": "reality.example.com",
                "server_port": 443,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "tls": {
                    "enabled": true,
                    "server_name": "www.apple.com",
                    "reality": {
                        "enabled": true,
                        "public_key": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
                        "short_id": "01ab"
                    }
                }
            },
            {
                "type": "hysteria2",
                "tag": "hy2-proxy",
                "server": "hy2.example.com",
                "server_port": 443,
                "password": "password123",
                "up_mbps": 100,
                "down_mbps": 100
            },
            {
                "type": "ssh",
                "tag": "ssh-proxy",
                "server": "ssh.example.com",
                "server_port": 22,
                "user": "proxyuser",
                "password": "secret"
            },
            {
                "type": "tuic",
                "tag": "tuic-proxy",
                "server": "tuic.example.com",
                "server_port": 443,
                "uuid": "11111111-2222-3333-4444-555555555555",
                "password": "tuicpass"
            },
            {
                "type": "urltest",
                "tag": "auto-select",
                "outbounds": ["reality-proxy", "hy2-proxy", "ssh-proxy", "tuic-proxy"],
                "url": "https://www.gstatic.com/generate_204",
                "interval": "5m"
            },
            {
                "type": "direct",
                "tag": "direct"
            }
        ],
        "route": {
            "rules": [
                {
                    "domain": ["google.com"],
                    "outbound": "reality-proxy"
                },
                {
                    "network": "udp",
                    "outbound": "hy2-proxy"
                }
            ],
            "final": "auto-select"
        }
    }"#;

    let tmp = write_cfg(cfg);
    
    let rust_bin = workspace_bin("check").to_string_lossy().to_string();
    let rust_result = run_check(&rust_bin, tmp.path().to_str().unwrap());
    assert!(rust_result.is_some(), "Rust check should execute");
    let (rust_success, rust_output) = rust_result.unwrap();
    
    if let Some(go_bin_path) = go_bin() {
        let go_result = run_check(&go_bin_path, tmp.path().to_str().unwrap());
        if let Some((go_success, go_output)) = go_result {
            println!("Rust result: {}", rust_success);
            println!("Go result: {}", go_success);
            assert_eq!(
                rust_success, go_success,
                "Rust and Go should have same validation result for mixed P0 config"
            );
        }
    }
    
    assert!(rust_success, "Rust should accept valid mixed P0 config. Output: {}", rust_output);
}
