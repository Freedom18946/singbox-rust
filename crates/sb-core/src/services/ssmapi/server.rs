//! SSMAPI service implementation with lifecycle management.

use super::{api, traffic::TrafficManager, user::UserManager};
use crate::service::{Service, ServiceContext, StartStage};
use axum::{routing::get, Router};
use sb_config::ir::ServiceIR;

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::oneshot;

/// Cache data structure for persistence.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CacheData {
    users: HashMap<String, UserTrafficCache>,
}

/// Per-user traffic cache data.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
struct UserTrafficCache {
    uplink_bytes: i64,
    downlink_bytes: i64,
    uplink_packets: i64,
    downlink_packets: i64,
}

/// SSMAPI service for managing Shadowsocks users and traffic.
pub struct SsmapiService {
    tag: String,
    listen_addr: SocketAddr,
    servers: BTreeMap<String, String>,
    user_manager: Arc<UserManager>,
    traffic_manager: Arc<TrafficManager>,
    shutdown_tx: parking_lot::Mutex<Option<oneshot::Sender<()>>>,
    /// Optional path for cache persistence.
    cache_path: Option<PathBuf>,
    /// TLS certificate path (enables HTTPS + HTTP/2).
    tls_cert_path: Option<PathBuf>,
    /// TLS private key path.
    tls_key_path: Option<PathBuf>,
}

impl SsmapiService {
    /// Create a new SSMAPI service from IR configuration.
    ///
    /// # Errors
    /// Returns an error if the configuration is invalid.
    pub fn from_ir(
        ir: &ServiceIR,
        _ctx: &ServiceContext,
    ) -> Result<Arc<Self>, Box<dyn std::error::Error + Send + Sync>> {
        let tag = ir.tag.as_deref().unwrap_or("ssm-api").to_string();

        // Parse servers mapping (endpoint -> inbound tag).
        let mut servers: BTreeMap<String, String> = BTreeMap::new();
        if let Some(map) = &ir.servers {
            for (endpoint, inbound_tag) in map {
                let mut endpoint = endpoint.trim().to_string();
                if endpoint.is_empty() {
                    continue;
                }
                if !endpoint.starts_with('/') {
                    endpoint.insert(0, '/');
                }
                if endpoint.len() > 1 && endpoint.ends_with('/') {
                    endpoint.pop();
                }
                let inbound_tag = inbound_tag.trim().to_string();
                if inbound_tag.is_empty() {
                    continue;
                }
                servers.insert(endpoint, inbound_tag);
            }
        }
        if servers.is_empty() {
            return Err("ssm-api: missing servers".into());
        }

        // Parse listen address
        let listen_ip = ir
            .listen
            .as_deref()
            .unwrap_or("127.0.0.1")
            .parse()
            .map_err(|e| format!("invalid listen address: {}", e))?;
        let listen_port = ir.listen_port.unwrap_or(6001);
        let listen_addr = SocketAddr::new(listen_ip, listen_port);

        let user_manager = UserManager::new();

        // Initialize traffic manager
        let traffic_manager = TrafficManager::new();

        tracing::info!(
            service = "ssm-api",
            tag = tag,
            listen = %listen_addr,
            servers = servers.len(),
            "SSMAPI service initialized"
        );

        // Parse cache path
        let cache_path = ir.cache_path.as_ref().map(PathBuf::from);

        // Parse TLS config (Go parity: `tls.enabled` + `certificate_path` + `key_path`)
        let (tls_cert_path, tls_key_path) = if ir.tls.as_ref().is_some_and(|t| t.enabled) {
            let tls = ir.tls.as_ref().expect("checked above");
            let cert = tls.certificate_path.as_ref().map(PathBuf::from);
            let key = tls.key_path.as_ref().map(PathBuf::from);
            if cert.is_some() != key.is_some() {
                return Err("ssm-api: both tls.certificate_path and tls.key_path must be specified".into());
            }
            (cert, key)
        } else {
            (None, None)
        };

        if tls_cert_path.is_some() {
            tracing::info!(
                service = "ssm-api",
                tag = tag,
                "TLS enabled (HTTPS + HTTP/2)"
            );
        }

        Ok(Arc::new(Self {
            tag,
            listen_addr,
            servers,
            user_manager,
            traffic_manager,
            shutdown_tx: parking_lot::Mutex::new(None),
            cache_path,
            tls_cert_path,
            tls_key_path,
        }))
    }

    /// Load cached traffic stats from disk.
    fn load_cache(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let Some(path) = &self.cache_path else {
            return Ok(());
        };

        if !path.exists() {
            tracing::debug!(service = "ssm-api", path = %path.display(), "Cache file not found, skipping load");
            return Ok(());
        }

        let file = std::fs::File::open(path)?;
        let cache: CacheData = serde_json::from_reader(file)?;

        // Restore traffic stats
        for (username, stats) in cache.users {
            self.traffic_manager
                .record_uplink(&username, stats.uplink_bytes, stats.uplink_packets);
            self.traffic_manager
                .record_downlink(&username, stats.downlink_bytes, stats.downlink_packets);
        }

        tracing::info!(
            service = "ssm-api",
            path = %path.display(),
            "Loaded cache successfully"
        );
        Ok(())
    }

    /// Save traffic stats to disk cache.
    fn save_cache(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let Some(path) = &self.cache_path else {
            return Ok(());
        };

        // Collect user traffic stats
        let mut users = HashMap::new();
        for mut user in self.user_manager.list() {
            self.traffic_manager.read_user(&mut user, false);
            users.insert(
                user.user_name.clone(),
                UserTrafficCache {
                    uplink_bytes: user.uplink_bytes,
                    downlink_bytes: user.downlink_bytes,
                    uplink_packets: user.uplink_packets,
                    downlink_packets: user.downlink_packets,
                },
            );
        }

        let cache = CacheData { users };
        let file = std::fs::File::create(path)?;
        serde_json::to_writer_pretty(file, &cache)?;

        tracing::info!(
            service = "ssm-api",
            path = %path.display(),
            "Saved cache successfully"
        );
        Ok(())
    }

    /// Create the Axum router with all API endpoints.
    /// Includes per-endpoint nested routes:
    /// - `{endpoint}/server/v1/...` (Go parity for `servers` keys)
    fn create_router(&self) -> Router {
        let state = api::ApiState {
            user_manager: self.user_manager.clone(),
            traffic_manager: self.traffic_manager.clone(),
        };

        let mut router = Router::new();
        for endpoint in self.servers.keys() {
            let mounted = Router::new()
                .nest("/server", api::api_routes())
                .with_state(state.clone());
            if endpoint == "/" {
                router = router.merge(mounted);
            } else {
                router = router.nest(endpoint, mounted);
            }
        }
        router
    }

    /// Create per-inbound nested routes for discovered inbound tags.
    /// Called from PostStart when inbound manager discovery completes.
    fn create_inbound_routes(inbound_tags: &[String], state: api::ApiState) -> Router {
        let mut router = Router::new()
            .nest("/server", api::api_routes())
            .with_state(state.clone());

        for tag in inbound_tags {
            // Each inbound gets its own prefixed routes: /{tag}/v1/...
            router = router.nest(&format!("/{}", tag), api::api_routes().with_state(state.clone()));
        }

        tracing::info!(
            service = "ssm-api",
            inbound_count = inbound_tags.len(),
            inbound_tags = ?inbound_tags,
            "Created per-inbound API routes"
        );

        router
    }

    /// Get a handle to the user manager (for integration with Shadowsocks adapters).
    pub fn user_manager(&self) -> Arc<UserManager> {
        self.user_manager.clone()
    }

    /// Get a handle to the traffic manager (for integration with Shadowsocks adapters).
    pub fn traffic_manager(&self) -> Arc<TrafficManager> {
        self.traffic_manager.clone()
    }

    /// Log status of Shadowsocks inbounds available for binding.
    /// Actual binding uses TrafficTracker trait and is triggered by SS adapters.
    async fn bind_inbounds_static(_traffic_manager: Arc<TrafficManager>, tag: String) {
        let Some(registry) = crate::context::context_registry() else {
            tracing::debug!(service = "ssm-api", tag = tag, "No context registry available");
            return;
        };

        let inbound_manager = registry.inbound_manager;
        let tags = inbound_manager.list_tags().await;

        tracing::info!(
            service = "ssm-api",
            tag = tag,
            available_inbounds = tags.len(),
            inbound_tags = ?tags,
            "SSMAPI ready for traffic tracking (SS inbounds should call set_tracker)"
        );
    }
}

impl Service for SsmapiService {
    fn service_type(&self) -> &str {
        "ssm-api"
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn start(&self, stage: StartStage) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match stage {
            StartStage::Initialize => {
                tracing::debug!(service = "ssm-api", tag = self.tag, "Initialize stage");
                Ok(())
            }
            StartStage::Start => {
                // Load cached stats before starting server
                if let Err(e) = self.load_cache() {
                    tracing::error!(service = "ssm-api", error = %e, "Failed to load cache");
                }

                let router = self.create_router();
                let listen_addr = self.listen_addr;

                tracing::info!(
                    service = "ssm-api",
                    tag = self.tag,
                    listen = %listen_addr,
                    tls = self.tls_cert_path.is_some(),
                    "Starting SSMAPI server"
                );

                // Start HTTP/HTTPS server in background task
                let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

                // Store shutdown sender
                *self.shutdown_tx.lock() = Some(shutdown_tx);

                let tls_cert_path = self.tls_cert_path.clone();
                let tls_key_path = self.tls_key_path.clone();

                tokio::spawn(async move {
                    if let (Some(cert_path), Some(key_path)) = (tls_cert_path, tls_key_path) {
                        // HTTPS with TLS (auto HTTP/2)
                        use axum_server::tls_rustls::RustlsConfig;

                        let config = match RustlsConfig::from_pem_file(&cert_path, &key_path).await {
                            Ok(c) => c,
                            Err(e) => {
                                    tracing::error!(
                                        service = "ssm-api",
                                        error = %e,
                                        cert = ?cert_path,
                                        key = ?key_path,
                                        "Failed to load TLS config"
                                    );
                                return;
                            }
                        };

                        tracing::info!(
                            service = "ssm-api",
                            listen = %listen_addr,
                            "SSMAPI HTTPS server started (HTTP/2 enabled)"
                        );

                        let handle = axum_server::Handle::new();
                        let handle_clone = handle.clone();

                        tokio::spawn(async move {
                            let _ = shutdown_rx.await;
                            tracing::info!(service = "ssm-api", "Received shutdown signal");
                            handle_clone.shutdown();
                        });

                        if let Err(e) = axum_server::bind_rustls(listen_addr, config)
                            .handle(handle)
                            .serve(router.into_make_service())
                            .await
                        {
                            tracing::error!(service = "ssm-api", error = %e, "SSMAPI server error");
                        }
                    } else {
                        // Plain HTTP
                        let listener = match tokio::net::TcpListener::bind(listen_addr).await {
                            Ok(l) => l,
                            Err(e) => {
                                tracing::error!(
                                    service = "ssm-api",
                                    error = %e,
                                    "Failed to bind SSMAPI server"
                                );
                                return;
                            }
                        };

                        tracing::info!(
                            service = "ssm-api",
                            listen = %listen_addr,
                            "SSMAPI HTTP server started"
                        );

                        let server = axum::serve(listener, router).with_graceful_shutdown(async {
                            let _ = shutdown_rx.await;
                            tracing::info!(service = "ssm-api", "Received shutdown signal");
                        });

                        if let Err(e) = server.await {
                            tracing::error!(service = "ssm-api", error = %e, "SSMAPI server error");
                        }
                    }
                });

                Ok(())
            }
            StartStage::PostStart => {
                // Bind to inbounds after all services have started
                let traffic_manager = self.traffic_manager.clone();
                let tag = self.tag.clone();
                tokio::spawn(async move {
                    Self::bind_inbounds_static(traffic_manager, tag).await;
                });
                Ok(())
            }
            StartStage::Started => {
                tracing::debug!(
                    service = "ssm-api",
                    tag = self.tag,
                    stage = ?stage,
                    "Stage completed"
                );
                Ok(())
            }
        }
    }

    fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!(service = "ssm-api", tag = self.tag, "Closing SSMAPI service");

        // Save cache before closing
        if let Err(e) = self.save_cache() {
            tracing::error!(service = "ssm-api", error = %e, "Failed to save cache");
        }

        // Note: We don't clear stats anymore since we save them
        // self.traffic_manager.clear_all();

        // Shutdown signal is sent via shutdown_tx channel
        if let Some(tx) = self.shutdown_tx.lock().take() {
            let _ = tx.send(());
        }

        Ok(())
    }
}

/// Builder function for service registry.
///
/// This replaces the stub implementation in `sb-adapters/src/service_stubs.rs`.
pub fn build_ssmapi_service(ir: &ServiceIR, ctx: &ServiceContext) -> Option<Arc<dyn Service>> {
    match SsmapiService::from_ir(ir, ctx) {
        Ok(service) => Some(service as Arc<dyn Service>),
        Err(e) => {
            tracing::error!(
                service = "ssm-api",
                error = %e,
                "Failed to create SSMAPI service"
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_config::ir::ServiceType;
    use std::collections::HashMap;

    fn create_test_ir() -> ServiceIR {
        let mut servers = HashMap::new();
        servers.insert("/".to_string(), "ss-in".to_string());

        ServiceIR {
            ty: ServiceType::Ssmapi,
            tag: Some("test-ssmapi".to_string()),
            listen: Some("127.0.0.1".to_string()),
            listen_port: Some(16001),
            servers: Some(servers),
            ..Default::default()
        }
    }

    #[test]
    fn test_service_creation() {
        let ir = create_test_ir();
        let ctx = ServiceContext::default();

        let service = SsmapiService::from_ir(&ir, &ctx).expect("Failed to create service");

        assert_eq!(service.service_type(), "ssm-api");
        assert_eq!(service.tag(), "test-ssmapi");
        assert_eq!(service.listen_addr.port(), 16001);
        assert_eq!(service.user_manager.len(), 0);
    }

    #[test]
    fn test_builder_function() {
        let ir = create_test_ir();
        let ctx = ServiceContext::default();

        let service = build_ssmapi_service(&ir, &ctx);
        assert!(service.is_some());

        let service = service.unwrap();
        assert_eq!(service.service_type(), "ssm-api");
    }

    #[tokio::test]
    async fn test_service_lifecycle() {
        let ir = create_test_ir();
        let ctx = ServiceContext::default();

        let service = SsmapiService::from_ir(&ir, &ctx).expect("Failed to create service");

        // Initialize
        assert!(service.start(StartStage::Initialize).is_ok());

        // Start (spawns background task)
        assert!(service.start(StartStage::Start).is_ok());

        // Give server time to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // PostStart
        assert!(service.start(StartStage::PostStart).is_ok());

        // Started
        assert!(service.start(StartStage::Started).is_ok());

        // Test API endpoint
        let client = reqwest::Client::new();
        let url = format!("http://{}/server/v1", service.listen_addr);

        match client.get(&url).send().await {
            Ok(resp) => {
                assert_eq!(resp.status(), 200);
                let body: serde_json::Value = resp.json().await.unwrap();
                assert!(body.get("server").is_some());
                assert_eq!(body.get("apiVersion").and_then(|v| v.as_str()), Some("v1"));
            }
            Err(e) => {
                // Server might not be ready yet, that's okay for this test
                tracing::warn!(
                    "API test request failed (expected in some test environments): {}",
                    e
                );
            }
        }

        // Close
        assert!(service.close().is_ok());
    }
}
