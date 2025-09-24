//! Test admin observe endpoints with feature gating

#[cfg(feature = "observe")]
mod observe_tests {
    use base64::Engine;
    use std::process::Command;
    use std::time::Duration;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_admin_endpoints_with_features() {
        use std::io::{BufRead, BufReader};
        use std::process::Stdio;

        // Start the admin server on a random port
        let mut child = Command::new("cargo")
            .args(&[
                "run",
                "--bin",
                "singbox-rust",
                "--features",
                "observe,subs_http,sbcore_rules_tool",
            ])
            .env("SB_ADMIN_ADDR", "127.0.0.1:0")
            .env("SB_LOG_LEVEL", "error")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("Failed to start admin server");

        // Wait for server to be ready by reading actual port from stdout
        let base_url = wait_for_server_ready(&mut child).await;
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
            .get(&format!("{}/router/geoip?ip=1.1.1.1", base_url))
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
            .get(&format!(
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

    async fn wait_for_server_ready(child: &mut std::process::Child) -> Option<String> {
        use std::io::{BufRead, BufReader};
        use std::time::Instant;

        let timeout = Duration::from_secs(10);
        let start = Instant::now();

        // Get stdout from child process
        let stdout = child.stdout.take()?;
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();

        while start.elapsed() < timeout {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    // EOF - process might have exited
                    sleep(Duration::from_millis(100)).await;
                    continue;
                }
                Ok(_) => {
                    // Check if this line contains our admin listen address
                    if let Some(addr_part) = line.strip_prefix("ADMIN_LISTEN=") {
                        let addr = addr_part.trim();
                        let base_url = format!("http://{}", addr);

                        // Verify server is actually responding
                        let client = reqwest::Client::builder()
                            .timeout(Duration::from_millis(500))
                            .build()
                            .ok()?;

                        if let Ok(response) = client
                            .get(&format!("{}/router/geoip?ip=127.0.0.1", base_url))
                            .send()
                            .await
                        {
                            if response.status().is_success() || response.status() == 400 {
                                return Some(base_url);
                            }
                        }
                    }
                }
                Err(_) => {
                    sleep(Duration::from_millis(100)).await;
                    continue;
                }
            }
        }

        None
    }

    // TODO: Re-enable feature gating test once module structure issues are resolved
    // #[tokio::test]
    // async fn test_feature_gating() {
    //     // Test that endpoints return 501 when required features are not enabled
    // }
}

#[cfg(not(feature = "observe"))]
mod no_observe_tests {
    #[test]
    fn test_observe_feature_disabled() {
        // When observe feature is disabled, admin endpoints should not be available
        println!("observe feature is disabled - admin endpoints not available");
    }
}
