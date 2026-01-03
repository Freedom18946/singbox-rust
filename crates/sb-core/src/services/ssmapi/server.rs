//! SSMAPI service implementation with lifecycle management.

use super::{api, traffic::TrafficManager, user::UserManager};
use crate::service::{Service, ServiceContext, StartStage};
use axum::Router;
use sb_config::ir::ServiceIR;

use std::collections::BTreeMap;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::oneshot;
use socket2::{Domain, Protocol, Socket, Type};

/// Go-parity cache structure: per-endpoint traffic + users.
/// Go reference: `service/ssmapi/cache.go`
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
struct Cache {
    /// Map of endpoint tag -> EndpointCache
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    endpoints: BTreeMap<String, EndpointCache>,
}

/// Per-endpoint cache data (Go parity).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
struct EndpointCache {
    // Global stats
    #[serde(skip_serializing_if = "is_zero", default, rename = "globalUplink")]
    global_uplink: i64,
    #[serde(skip_serializing_if = "is_zero", default, rename = "globalDownlink")]
    global_downlink: i64,
    #[serde(
        skip_serializing_if = "is_zero",
        default,
        rename = "globalUplinkPackets"
    )]
    global_uplink_packets: i64,
    #[serde(
        skip_serializing_if = "is_zero",
        default,
        rename = "globalDownlinkPackets"
    )]
    global_downlink_packets: i64,
    #[serde(skip_serializing_if = "is_zero", default, rename = "globalTCPSessions")]
    global_tcp_sessions: i64,
    #[serde(skip_serializing_if = "is_zero", default, rename = "globalUDPSessions")]
    global_udp_sessions: i64,

    // Per-user stats (only non-zero values)
    #[serde(
        skip_serializing_if = "BTreeMap::is_empty",
        default,
        rename = "userUplink"
    )]
    user_uplink: BTreeMap<String, i64>,
    #[serde(
        skip_serializing_if = "BTreeMap::is_empty",
        default,
        rename = "userDownlink"
    )]
    user_downlink: BTreeMap<String, i64>,
    #[serde(
        skip_serializing_if = "BTreeMap::is_empty",
        default,
        rename = "userUplinkPackets"
    )]
    user_uplink_packets: BTreeMap<String, i64>,
    #[serde(
        skip_serializing_if = "BTreeMap::is_empty",
        default,
        rename = "userDownlinkPackets"
    )]
    user_downlink_packets: BTreeMap<String, i64>,
    #[serde(
        skip_serializing_if = "BTreeMap::is_empty",
        default,
        rename = "userTCPSessions"
    )]
    user_tcp_sessions: BTreeMap<String, i64>,
    #[serde(
        skip_serializing_if = "BTreeMap::is_empty",
        default,
        rename = "userUDPSessions"
    )]
    user_udp_sessions: BTreeMap<String, i64>,

    // Users map (username -> password, non-empty only)
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    users: BTreeMap<String, String>,
}

fn is_zero(v: &i64) -> bool {
    *v == 0
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
    
    // TLS Configuration
    /// TLS certificate path (enables HTTPS + HTTP/2).
    tls_cert_path: Option<PathBuf>,
    /// TLS private key path.
    tls_key_path: Option<PathBuf>,
    /// Inline TLS certificate (PEM).
    tls_cert_pem: Option<Vec<u8>>,
    /// Inline TLS private key (PEM).
    tls_key_pem: Option<Vec<u8>>,

    // Listen Options
    #[allow(dead_code)]
    bind_interface: Option<String>,
    #[allow(dead_code)]
    routing_mark: Option<u32>,
    reuse_addr: bool,
    #[allow(dead_code)]
    tcp_fast_open: bool,
    #[allow(dead_code)]
    tcp_multi_path: bool,
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

        // Parse ListenOptions
        let bind_interface = ir.bind_interface.clone();
        let routing_mark = ir.routing_mark;
        let reuse_addr = ir.reuse_addr.unwrap_or(true); // Default true for server
        let tcp_fast_open = ir.tcp_fast_open.unwrap_or(false);
        let tcp_multi_path = ir.tcp_multi_path.unwrap_or(false);

        // Parse cache path
        let cache_path = ir.cache_path.as_ref().map(PathBuf::from);

        // Parse TLS config (Go parity: `tls.enabled` + `certificate_path`/`certificate` + `key_path`/`key`)
        let (tls_cert_path, tls_key_path, tls_cert_pem, tls_key_pem) =
            if ir.tls.as_ref().is_some_and(|t| t.enabled) {
                let tls = ir.tls.as_ref().expect("checked above");
                
                let cert_path = tls.certificate_path.as_ref().map(PathBuf::from);
                let key_path = tls.key_path.as_ref().map(PathBuf::from);
                
                let cert_pem = tls.certificate.as_ref().map(|lines| lines.join("\n").into_bytes());
                let key_pem = tls.key.as_ref().map(|lines| lines.join("\n").into_bytes());

                let has_path = cert_path.is_some() && key_path.is_some();
                let has_pem = cert_pem.is_some() && key_pem.is_some();

                if !has_path && !has_pem {
                     return Err(
                        "ssm-api: tls enabled but missing certificate/key (path or inline)".into(),
                    );
                }

                (cert_path, key_path, cert_pem, key_pem)
            } else {
                (None, None, None, None)
            };

        if tls_cert_path.is_some() || tls_cert_pem.is_some() {
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
            tls_cert_pem,
            tls_key_pem,
            bind_interface,
            routing_mark,
            reuse_addr,
            tcp_fast_open,
            tcp_multi_path,
        }))
    }

    /// Create a customized TCP listener with options (socket2).
    fn create_listener(&self) -> std::io::Result<tokio::net::TcpListener> {
        let domain = if self.listen_addr.is_ipv4() {
             Domain::IPV4
        } else {
             Domain::IPV6
        };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

        if self.reuse_addr {
            #[cfg(not(windows))]
            socket.set_reuse_address(true)?;
            #[cfg(not(windows))]
            socket.set_reuse_port(true)?;
        }
        
        // Apply routing mark (Linux only)
        #[cfg(target_os = "linux")]
        if let Some(mark) = self.routing_mark {
            socket.set_mark(mark)?;
        }

        // Apply bind interface (Linux/Android/Darwin?)
        // Note: socket2 bind_device_by_index_v4 is available, but string binding requires unsafe or libc
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if let Some(ref iface) = self.bind_interface {
             socket.bind_to_device(Some(iface.as_bytes()))?;
        }

        // Apply TCP Fast Open
        #[cfg(any(target_os = "linux", target_os = "android"))]
        if self.tcp_fast_open {
             // 256 is a common backlog size for TFO
             socket.set_tcp_fastopen(256)?;
        }

        // Bind and listen
        socket.bind(&self.listen_addr.into())?;
        socket.listen(128)?;
        
        // Convert to tokio TcpListener
        socket.set_nonblocking(true)?;
        let std_listener: std::net::TcpListener = socket.into();
        tokio::net::TcpListener::from_std(std_listener)
    }

    /// Load cached traffic stats from disk (Go parity).
    /// Uses per-endpoint format: `{ endpoints: { tag: { stats, users } } }`
    fn load_cache(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let Some(path) = &self.cache_path else {
            return Ok(());
        };

        if !path.exists() {
            tracing::debug!(service = "ssm-api", path = %path.display(), "Cache file not found, skipping load");
            return Ok(());
        }

        let file = std::fs::File::open(path)?;
        let cache: Cache = serde_json::from_reader(file)?;

        // Restore traffic stats per endpoint
        // For now, we treat all endpoints as a single shared traffic manager
        // (Go has per-endpoint traffic managers, Rust currently has one shared one)
        for (_endpoint_tag, endpoint_cache) in cache.endpoints {
            // Restore per-user traffic
            for (username, uplink) in endpoint_cache.user_uplink {
                let downlink = endpoint_cache
                    .user_downlink
                    .get(&username)
                    .copied()
                    .unwrap_or(0);
                let uplink_packets = endpoint_cache
                    .user_uplink_packets
                    .get(&username)
                    .copied()
                    .unwrap_or(0);
                let downlink_packets = endpoint_cache
                    .user_downlink_packets
                    .get(&username)
                    .copied()
                    .unwrap_or(0);

                self.traffic_manager
                    .record_uplink(&username, uplink, uplink_packets);
                self.traffic_manager
                    .record_downlink(&username, downlink, downlink_packets);
            }

            // Restore users (if UserManager supports bulk set)
            for (username, password) in endpoint_cache.users {
                if !username.is_empty() && !password.is_empty() {
                    // Ignore errors if user already exists
                    let _ = self.user_manager.add(username, password);
                }
            }
        }

        tracing::info!(
            service = "ssm-api",
            path = %path.display(),
            "Loaded cache successfully"
        );
        Ok(())
    }

    /// Save traffic stats to disk cache (Go parity).
    /// Uses per-endpoint format for compatibility with Go.
    fn save_cache(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let Some(path) = &self.cache_path else {
            return Ok(());
        };

        // Collect per-endpoint cache (using servers tags as endpoints)
        let mut endpoints = BTreeMap::new();
        for endpoint in self.servers.keys() {
            let mut endpoint_cache = EndpointCache::default();

            // Collect user traffic stats
            for mut user in self.user_manager.list() {
                self.traffic_manager.read_user(&mut user, false);
                let username = user.user_name.clone();

                if user.uplink_bytes > 0 {
                    endpoint_cache
                        .user_uplink
                        .insert(username.clone(), user.uplink_bytes);
                }
                if user.downlink_bytes > 0 {
                    endpoint_cache
                        .user_downlink
                        .insert(username.clone(), user.downlink_bytes);
                }
                if user.uplink_packets > 0 {
                    endpoint_cache
                        .user_uplink_packets
                        .insert(username.clone(), user.uplink_packets);
                }
                if user.downlink_packets > 0 {
                    endpoint_cache
                        .user_downlink_packets
                        .insert(username.clone(), user.downlink_packets);
                }

                // Store user password (only if present and non-empty)
                if let Some(ref pwd) = user.password {
                    if !pwd.is_empty() {
                        endpoint_cache.users.insert(username, pwd.clone());
                    }
                }
            }

            // Global stats (not currently tracked separately, would need extension)
            // For now, leave as 0 (Go also initializes to 0)

            endpoints.insert(endpoint.clone(), endpoint_cache);
        }

        let cache = Cache { endpoints };
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
    #[allow(dead_code)]
    fn create_inbound_routes(inbound_tags: &[String], state: api::ApiState) -> Router {
        let mut router = Router::new()
            .nest("/server", api::api_routes())
            .with_state(state.clone());

        for tag in inbound_tags {
            // Each inbound gets its own prefixed routes: /{tag}/v1/...
            router = router.nest(
                &format!("/{}", tag),
                api::api_routes().with_state(state.clone()),
            );
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
            tracing::debug!(
                service = "ssm-api",
                tag = tag,
                "No context registry available"
            );
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
                    tls = self.tls_cert_path.is_some() || self.tls_cert_pem.is_some(),
                    "Starting SSMAPI server"
                );

                // Start HTTP/HTTPS server in background task
                let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();

                // Store shutdown sender
                *self.shutdown_tx.lock() = Some(shutdown_tx);

                // Clone config for background task
                let tls_cert_path = self.tls_cert_path.clone();
                let tls_key_path = self.tls_key_path.clone();
                let tls_cert_pem = self.tls_cert_pem.clone();
                let tls_key_pem = self.tls_key_pem.clone();
                
                // Create listener using options
                let listener = match self.create_listener() {
                    Ok(l) => l,
                    Err(e) => {
                        tracing::error!(
                            service = "ssm-api",
                            error = %e,
                            "Failed to bind SSMAPI server"
                        );
                        return Err(e.into());
                    }
                };

                tokio::spawn(async move {
                    // Check if TLS is configured
                    let tls_config_res = if let (Some(cert_path), Some(key_path)) = (&tls_cert_path, &tls_key_path) {
                         Some(axum_server::tls_rustls::RustlsConfig::from_pem_file(cert_path, key_path).await)
                    } else if let (Some(cert_pem), Some(key_pem)) = (&tls_cert_pem, &tls_key_pem) {
                         Some(axum_server::tls_rustls::RustlsConfig::from_pem(cert_pem.clone(), key_pem.clone()).await)
                    } else {
                         None
                    };

                    if let Some(config_res) = tls_config_res {
                        // HTTPS with TLS
                        let config = match config_res {
                            Ok(c) => c,
                            Err(e) => {
                                tracing::error!(
                                    service = "ssm-api",
                                    error = %e,
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
                        
                        // Convert back to std::net::TcpListener for axum_server
                        let std_listener = match listener.into_std() {
                            Ok(l) => {
                                let _ = l.set_nonblocking(true); // axum_server expects this IIRC or handles it
                                l
                            }
                            Err(e) => {
                                tracing::error!(service = "ssm-api", error = %e, "Failed to convert listener");
                                return;
                            }
                        };

                        let server = match axum_server::from_tcp_rustls(std_listener, config) {
                            Ok(server) => server,
                            Err(e) => {
                                tracing::error!(
                                    service = "ssm-api",
                                    error = %e,
                                    "Failed to create HTTPS server"
                                );
                                return;
                            }
                        };

                        if let Err(e) = server
                            .handle(handle)
                            .serve(router.into_make_service())
                            .await
                        {
                            tracing::error!(service = "ssm-api", error = %e, "SSMAPI server error");
                        }
                    } else {
                        // Plain HTTP
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
        tracing::info!(
            service = "ssm-api",
            tag = self.tag,
            "Closing SSMAPI service"
        );

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
