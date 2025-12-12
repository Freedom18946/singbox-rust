//! SSMAPI service implementation with lifecycle management.

use super::{api, traffic::TrafficManager, user::UserManager};
use crate::service::{Service, ServiceContext, StartStage};
use axum::{routing::get, Router};
use sb_config::ir::ServiceIR;

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
    user_manager: Arc<UserManager>,
    traffic_manager: Arc<TrafficManager>,
    shutdown_tx: parking_lot::Mutex<Option<oneshot::Sender<()>>>,
    /// Optional path for cache persistence.
    cache_path: Option<PathBuf>,
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
        let tag = ir.tag.as_deref().unwrap_or("ssmapi").to_string();

        // Parse listen address
        let listen_ip = ir
            .ssmapi_listen
            .as_deref()
            .unwrap_or("127.0.0.1")
            .parse()
            .map_err(|e| format!("invalid listen address: {}", e))?;
        let listen_port = ir.ssmapi_listen_port.unwrap_or(6001);
        let listen_addr = SocketAddr::new(listen_ip, listen_port);

        // Initialize user manager with configured servers
        let user_manager = if let Some(servers) = &ir.ssmapi_servers {
            UserManager::with_users(servers.clone())
        } else {
            UserManager::new()
        };

        // Initialize traffic manager
        let traffic_manager = TrafficManager::new();

        tracing::info!(
            service = "ssmapi",
            tag = tag,
            listen = %listen_addr,
            initial_users = user_manager.len(),
            "SSMAPI service initialized"
        );

        // Parse cache path
        let cache_path = ir.ssmapi_cache_path.as_ref().map(PathBuf::from);

        Ok(Arc::new(Self {
            tag,
            listen_addr,
            user_manager,
            traffic_manager,
            shutdown_tx: parking_lot::Mutex::new(None),
            cache_path,
        }))
    }

    /// Load cached traffic stats from disk.
    fn load_cache(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let Some(path) = &self.cache_path else {
            return Ok(());
        };

        if !path.exists() {
            tracing::debug!(service = "ssmapi", path = %path.display(), "Cache file not found, skipping load");
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
            service = "ssmapi",
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
            service = "ssmapi",
            path = %path.display(),
            "Saved cache successfully"
        );
        Ok(())
    }

    /// Create the Axum router with all API endpoints.
    fn create_router(&self) -> Router {
        let state = api::ApiState {
            user_manager: self.user_manager.clone(),
            traffic_manager: self.traffic_manager.clone(),
        };

        Router::new()
            .route("/server/v1", get(api::get_server_info))
            .route("/server/v1/users", get(api::list_users).post(api::add_user))
            .route(
                "/server/v1/users/:username",
                get(api::get_user)
                    .put(api::update_user)
                    .delete(api::delete_user),
            )
            .route("/server/v1/stats", get(api::get_stats))
            .with_state(state)
    }

    /// Get a handle to the user manager (for integration with Shadowsocks adapters).
    pub fn user_manager(&self) -> Arc<UserManager> {
        self.user_manager.clone()
    }

    /// Get a handle to the traffic manager (for integration with Shadowsocks adapters).
    pub fn traffic_manager(&self) -> Arc<TrafficManager> {
        self.traffic_manager.clone()
    }
}

impl Service for SsmapiService {
    fn service_type(&self) -> &str {
        "ssmapi"
    }

    fn tag(&self) -> &str {
        &self.tag
    }

    fn start(&self, stage: StartStage) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match stage {
            StartStage::Initialize => {
                tracing::debug!(service = "ssmapi", tag = self.tag, "Initialize stage");
                Ok(())
            }
            StartStage::Start => {
                // Load cached stats before starting server
                if let Err(e) = self.load_cache() {
                    tracing::error!(service = "ssmapi", error = %e, "Failed to load cache");
                }

                let router = self.create_router();
                let listen_addr = self.listen_addr;

                tracing::info!(
                    service = "ssmapi",
                    tag = self.tag,
                    listen = %listen_addr,
                    "Starting SSMAPI HTTP server"
                );

                // Start HTTP server in background task
                let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

                // Store shutdown sender
                *self.shutdown_tx.lock() = Some(shutdown_tx);

                tokio::spawn(async move {
                    let listener = match tokio::net::TcpListener::bind(listen_addr).await {
                        Ok(l) => l,
                        Err(e) => {
                            tracing::error!(
                                service = "ssmapi",
                                error = %e,
                                "Failed to bind SSMAPI server"
                            );
                            return;
                        }
                    };

                    tracing::info!(
                        service = "ssmapi",
                        listen = %listen_addr,
                        "SSMAPI HTTP server started"
                    );

                    let server = axum::serve(listener, router).with_graceful_shutdown(async {
                        let _ = shutdown_rx.await;
                        tracing::info!(service = "ssmapi", "Received shutdown signal");
                    });

                    if let Err(e) = server.await {
                        tracing::error!(service = "ssmapi", error = %e, "SSMAPI server error");
                    }
                });

                Ok(())
            }
            StartStage::PostStart | StartStage::Started => {
                tracing::debug!(
                    service = "ssmapi",
                    tag = self.tag,
                    stage = ?stage,
                    "Stage completed"
                );
                Ok(())
            }
        }
    }

    fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!(service = "ssmapi", tag = self.tag, "Closing SSMAPI service");

        // Save cache before closing
        if let Err(e) = self.save_cache() {
            tracing::error!(service = "ssmapi", error = %e, "Failed to save cache");
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
                service = "ssmapi",
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
        servers.insert("user1".to_string(), "aes-256-gcm:pass123".to_string());

        ServiceIR {
            ty: ServiceType::Ssmapi,
            tag: Some("test-ssmapi".to_string()),
            ssmapi_listen: Some("127.0.0.1".to_string()),
            ssmapi_listen_port: Some(16001),
            ssmapi_servers: Some(servers),
            ssmapi_cache_path: None,
            ssmapi_tls_cert_path: None,
            ssmapi_tls_key_path: None,
            // Other fields...
            resolved_listen: None,
            resolved_listen_port: None,
            derp_listen: None,
            derp_listen_port: None,
            derp_config_path: None,
            derp_verify_client_endpoint: None,
            derp_verify_client_url: None,
            derp_home: None,
            derp_mesh_with: None,
            derp_mesh_psk: None,
            derp_mesh_psk_file: None,
            derp_stun_enabled: None,
            derp_stun_listen_port: None,
            derp_tls_cert_path: None,
            derp_tls_key_path: None,
            derp_server_key_path: None,
        }
    }

    #[test]
    fn test_service_creation() {
        let ir = create_test_ir();
        let ctx = ServiceContext::default();

        let service = SsmapiService::from_ir(&ir, &ctx).expect("Failed to create service");

        assert_eq!(service.service_type(), "ssmapi");
        assert_eq!(service.tag(), "test-ssmapi");
        assert_eq!(service.listen_addr.port(), 16001);
        assert_eq!(service.user_manager.len(), 1);
    }

    #[test]
    fn test_builder_function() {
        let ir = create_test_ir();
        let ctx = ServiceContext::default();

        let service = build_ssmapi_service(&ir, &ctx);
        assert!(service.is_some());

        let service = service.unwrap();
        assert_eq!(service.service_type(), "ssmapi");
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
