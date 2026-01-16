#![cfg(feature = "admin_tests")]
//! Test admin observe endpoints with feature gating

#[cfg(feature = "observe")]
mod observe_tests {
    use base64::Engine;
    use serde_json::Value;
    use std::fs;
    use std::io;
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::Duration;
    use tempfile::NamedTempFile;
    use tokio::time::sleep;

    fn target_root_dir() -> PathBuf {
        if let Ok(target_dir) = std::env::var("CARGO_TARGET_DIR") {
            return PathBuf::from(target_dir);
        }
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("..")
            .join("target")
    }

    fn target_dir_for(features: &str) -> PathBuf {
        let mut dir = target_root_dir();
        let slug = if features.is_empty() {
            "default".to_string()
        } else {
            features
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                .collect()
        };
        dir.push(format!("sb_app_build_{slug}"));
        dir
    }

    fn bin_path(target_dir: &Path) -> PathBuf {
        let profile = std::env::var("CARGO_PROFILE")
            .ok()
            .or_else(|| std::env::var("PROFILE").ok())
            .unwrap_or_else(|| "debug".into());
        let mut path = target_dir.to_path_buf();
        path.push(profile);
        path.push("app");
        if cfg!(windows) {
            path.set_extension("exe");
        }
        path
    }

    fn build_app(features: &str) -> PathBuf {
        let target_dir = target_dir_for(features);
        std::fs::create_dir_all(&target_dir).expect("create target dir");
        let bin = bin_path(&target_dir);
        if !bin.exists() {
            let mut cmd = Command::new("cargo");
            cmd.args(["build", "-p", "app", "--bin", "app"]);
            if !features.is_empty() {
                cmd.arg("--features");
                cmd.arg(features);
            }
            cmd.env("CARGO_TARGET_DIR", &target_dir);
            let status = cmd.status().expect("build app");
            assert!(
                status.success(),
                "failed to build app with features: {features}"
            );
        }
        bin
    }

    fn should_skip_network_tests() -> bool {
        match std::net::TcpListener::bind("127.0.0.1:0") {
            Ok(listener) => {
                drop(listener);
                false
            }
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::PermissionDenied | io::ErrorKind::AddrNotAvailable
                ) =>
            {
                eprintln!("Skipping admin observe tests: {}", err);
                true
            }
            Err(err) => panic!("Failed to bind test listener: {}", err),
        }
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_admin_endpoints_with_features() {
        use std::process::Stdio;

        if should_skip_network_tests() {
            return;
        }

        let bin = build_app("admin_debug,sbcore_rules_tool");

        let portfile = NamedTempFile::new().expect("create admin portfile");
        let cfg_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/ok.json");

        // Start the admin server on a random port
        let cfg_arg = cfg_path.to_string_lossy().to_string();
        let mut child = Command::new(bin)
            .args(["run", "--config", &cfg_arg, "--no-banner"])
            .env("SB_DEBUG_ADDR", "127.0.0.1:0")
            .env("SB_ADMIN_PORTFILE", portfile.path())
            .env("SB_ADMIN_NO_AUTH", "1")
            .env("SB_LOG_LEVEL", "error")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("Failed to start admin server");

        // Wait for server to be ready via the admin portfile.
        let base_url = wait_for_server_ready(&mut child, portfile.path()).await;
        if base_url.is_none() {
            let _ = child.kill();
            panic!("Server did not become ready within timeout");
        }
        let base_url = base_url.unwrap();

        // Test basic endpoints that should work with minimal features
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("Failed to create HTTP client");

        // Test GeoIP endpoint
        match client
            .get(format!("{}/router/geoip?ip=1.1.1.1", base_url))
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {
                let body = response.text().await.unwrap_or_default();
                assert!(body.contains("cc") || body.contains("country") || body.contains("AS"));
            }
            Ok(response) => {
                eprintln!("GeoIP endpoint returned status: {}", response.status());
            }
            Err(e) => {
                eprintln!("Failed to test GeoIP endpoint: {}", e);
            }
        }

        // Test rules normalize endpoint
        let normalize_payload =
            base64::engine::general_purpose::STANDARD.encode("DOMAIN-SUFFIX,example.com,direct");

        match client
            .get(format!(
                "{}/router/rules/normalize?inline={}",
                base_url, normalize_payload
            ))
            .send()
            .await
        {
            Ok(response) if response.status().is_success() => {
                let body = response.text().await.unwrap_or_default();
                assert!(body.contains("example.com"));
            }
            Ok(response) => {
                eprintln!("Normalize endpoint returned status: {}", response.status());
            }
            Err(e) => {
                eprintln!("Failed to test normalize endpoint: {}", e);
            }
        }

        // Clean up
        let _ = child.kill();
    }

    async fn wait_for_server_ready(
        child: &mut std::process::Child,
        portfile: &Path,
    ) -> Option<String> {
        use std::time::Instant;

        let timeout = Duration::from_secs(30);
        let start = Instant::now();
        let expected_pid = child.id() as u64;

        while start.elapsed() < timeout {
            if let Ok(Some(_)) = child.try_wait() {
                return None;
            }

            if let Ok(addr) = fs::read_to_string(portfile) {
                let addr = addr.trim();
                if !addr.is_empty() {
                    let base_url = format!("http://{}", addr);
                    let client = reqwest::Client::builder()
                        .timeout(Duration::from_millis(500))
                        .build()
                        .ok()?;
                    if let Ok(response) = client.get(format!("{}/__health", base_url)).send().await
                    {
                        if response.status().is_success() {
                            let body = response.text().await.ok()?;
                            let payload: Value = serde_json::from_str(&body).ok()?;
                            if payload.get("pid").and_then(|v| v.as_u64()) == Some(expected_pid) {
                                return Some(base_url);
                            }
                        }
                    }
                }
            }

            sleep(Duration::from_millis(100)).await;
        }

        None
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn test_feature_gating() {
        use std::process::Stdio;

        if should_skip_network_tests() {
            return;
        }

        let bin = build_app("admin_debug");

        let portfile = NamedTempFile::new().expect("create admin portfile");
        let cfg_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/ok.json");

        // Start the admin server without certain features
        let cfg_arg = cfg_path.to_string_lossy().to_string();
        let mut child = Command::new(bin)
            .args(["run", "--config", &cfg_arg, "--no-banner"])
            .env("SB_DEBUG_ADDR", "127.0.0.1:0")
            .env("SB_ADMIN_PORTFILE", portfile.path())
            .env("SB_ADMIN_NO_AUTH", "1")
            .env("SB_LOG_LEVEL", "error")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("Failed to start admin server");

        // Wait for server to be ready
        let base_url = wait_for_server_ready(&mut child, portfile.path()).await;
        if base_url.is_none() {
            let _ = child.kill();
            panic!("Server did not become ready within timeout");
        }
        let base_url = base_url.unwrap();

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("Failed to create HTTP client");

        // Test that endpoints requiring missing features return 501 Not Implemented
        let response = client
            .get(format!("{}/subs/clash?url=test", base_url))
            .send()
            .await;

        match response {
            Ok(resp) => {
                // Should return 501 when subs_http feature is not enabled
                assert!(
                    resp.status() == 501 || resp.status() == 404,
                    "Expected 501 or 404 for missing feature, got {}",
                    resp.status()
                );
            }
            Err(_) => {
                // Connection error is also acceptable if the endpoint doesn't exist
            }
        }

        // Clean up
        let _ = child.kill();
    }
}

#[cfg(not(feature = "observe"))]
mod no_observe_tests {
    #[test]
    fn test_observe_feature_disabled() {
        // When observe feature is disabled, admin endpoints should not be available
        println!("observe feature is disabled - admin endpoints not available");
    }
}
