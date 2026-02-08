//! SSMAPI service implementation with lifecycle management.

use super::{api, registry, traffic::TrafficManager, user::UserManager};
use crate::service::{Service, ServiceContext, StartStage};
use axum::Router;
use sb_config::ir::ServiceIR;

use std::collections::{BTreeMap, HashMap, HashSet};

use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::oneshot;
use tokio::time::Duration;

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
    #[serde(skip_serializing_if = "is_zero", default)]
    global_uplink: i64,
    #[serde(skip_serializing_if = "is_zero", default)]
    global_downlink: i64,
    #[serde(skip_serializing_if = "is_zero", default)]
    global_uplink_packets: i64,
    #[serde(skip_serializing_if = "is_zero", default)]
    global_downlink_packets: i64,
    #[serde(skip_serializing_if = "is_zero", default)]
    global_tcp_sessions: i64,
    #[serde(skip_serializing_if = "is_zero", default)]
    global_udp_sessions: i64,

    // Per-user stats (only non-zero values)
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    user_uplink: BTreeMap<String, i64>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    user_downlink: BTreeMap<String, i64>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    user_uplink_packets: BTreeMap<String, i64>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    user_downlink_packets: BTreeMap<String, i64>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    user_tcp_sessions: BTreeMap<String, i64>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    user_udp_sessions: BTreeMap<String, i64>,

    // Users map (username -> password, non-empty only)
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    users: BTreeMap<String, String>,
}

/// Legacy cache format written by older Rust builds (camelCase JSON keys).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
struct LegacyCache {
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    endpoints: BTreeMap<String, LegacyEndpointCache>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
struct LegacyEndpointCache {
    #[serde(skip_serializing_if = "is_zero", default, rename = "globalUplink")]
    global_uplink: i64,
    #[serde(skip_serializing_if = "is_zero", default, rename = "globalDownlink")]
    global_downlink: i64,
    #[serde(skip_serializing_if = "is_zero", default, rename = "globalUplinkPackets")]
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

    #[serde(skip_serializing_if = "BTreeMap::is_empty", default, rename = "userUplink")]
    user_uplink: BTreeMap<String, i64>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default, rename = "userDownlink")]
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
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default, rename = "userTCPSessions")]
    user_tcp_sessions: BTreeMap<String, i64>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default, rename = "userUDPSessions")]
    user_udp_sessions: BTreeMap<String, i64>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    users: BTreeMap<String, String>,
}

fn is_zero(v: &i64) -> bool {
    *v == 0
}

#[derive(Clone)]
struct EndpointCtx {
    inbound_tag: String,
    server: Arc<dyn super::ManagedSSMServer>,
    user_manager: Arc<UserManager>,
    traffic_manager: Arc<TrafficManager>,
}

fn normalize_endpoint(raw: &str) -> Option<String> {
    let mut endpoint = raw.trim().to_string();
    if endpoint.is_empty() {
        return None;
    }
    if !endpoint.starts_with('/') {
        endpoint.insert(0, '/');
    }
    if endpoint.len() > 1 && endpoint.ends_with('/') {
        endpoint.pop();
    }
    Some(endpoint)
}

/// SSMAPI service for managing Shadowsocks users and traffic.
pub struct SsmapiService {
    tag: String,
    listen_addr: SocketAddr,
    endpoints: BTreeMap<String, EndpointCtx>,
    shutdown_tx: parking_lot::Mutex<Option<oneshot::Sender<()>>>,
    /// Optional path for cache persistence.
    cache_path: Option<PathBuf>,
    last_saved_cache: Arc<parking_lot::Mutex<Vec<u8>>>,
    save_task: parking_lot::Mutex<Option<tokio::task::JoinHandle<()>>>,

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
                let Some(endpoint) = normalize_endpoint(endpoint) else {
                    continue;
                };
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

        // Enforce inbound tag uniqueness to avoid multiple endpoints controlling the same inbound.
        let mut seen_inbounds: HashSet<String> = HashSet::new();
        for (endpoint, inbound_tag) in &servers {
            if !seen_inbounds.insert(inbound_tag.clone()) {
                return Err(format!(
                    "ssm-api: duplicate inbound tag '{}' (endpoint '{}')",
                    inbound_tag, endpoint
                )
                .into());
            }
        }

        // Bind per-endpoint managers and managed inbounds.
        let mut endpoints: BTreeMap<String, EndpointCtx> = BTreeMap::new();
        for (endpoint, inbound_tag) in &servers {
            let server = registry::get_managed_ssm_server(inbound_tag).ok_or_else(|| {
                format!(
                    "ssm-api: parse server endpoint '{}': inbound '{}' not found",
                    endpoint, inbound_tag
                )
            })?;
            if server.inbound_type() != "shadowsocks" {
                return Err(format!(
                    "ssm-api: parse server endpoint '{}': inbound/{}/{} is not a SSM server",
                    endpoint,
                    server.inbound_type(),
                    server.tag()
                )
                .into());
            }

            let traffic_manager = TrafficManager::new();
            server.set_tracker(traffic_manager.clone());
            let user_manager = UserManager::with_server(server.clone(), traffic_manager.clone());

            endpoints.insert(
                endpoint.clone(),
                EndpointCtx {
                    inbound_tag: inbound_tag.clone(),
                    server,
                    user_manager,
                    traffic_manager,
                },
            );
        }

        tracing::info!(
            service = "ssm-api",
            tag = tag,
            listen = %listen_addr,
            endpoints = endpoints.len(),
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

                let cert_pem = tls
                    .certificate
                    .as_ref()
                    .map(|lines| lines.join("\n").into_bytes());
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
            endpoints,
            shutdown_tx: parking_lot::Mutex::new(None),
            cache_path,
            last_saved_cache: Arc::new(parking_lot::Mutex::new(Vec::new())),
            save_task: parking_lot::Mutex::new(None),
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

        let cache_binary = std::fs::read(path)?;
        if cache_binary.is_empty() {
            return Ok(());
        }

        // Heuristic: legacy Rust cache (camelCase) would otherwise deserialize "successfully"
        // into the Go-parity struct because serde ignores unknown fields by default, but we'd
        // silently lose traffic stats. Detect and prefer legacy decoding when markers exist.
        let is_legacy_marker = std::str::from_utf8(&cache_binary)
            .ok()
            .is_some_and(|s| s.contains("\"userUplink\"") || s.contains("\"globalUplink\""));

        let cache = match serde_json::from_slice::<Cache>(&cache_binary) {
            Ok(v) if !is_legacy_marker => v,
            Ok(_) | Err(_) => match serde_json::from_slice::<LegacyCache>(&cache_binary) {
                Ok(legacy) => Cache {
                    endpoints: legacy
                        .endpoints
                        .into_iter()
                        .map(|(k, v)| {
                            (
                                k,
                                EndpointCache {
                                    global_uplink: v.global_uplink,
                                    global_downlink: v.global_downlink,
                                    global_uplink_packets: v.global_uplink_packets,
                                    global_downlink_packets: v.global_downlink_packets,
                                    global_tcp_sessions: v.global_tcp_sessions,
                                    global_udp_sessions: v.global_udp_sessions,
                                    user_uplink: v.user_uplink,
                                    user_downlink: v.user_downlink,
                                    user_uplink_packets: v.user_uplink_packets,
                                    user_downlink_packets: v.user_downlink_packets,
                                    user_tcp_sessions: v.user_tcp_sessions,
                                    user_udp_sessions: v.user_udp_sessions,
                                    users: v.users,
                                },
                            )
                        })
                        .collect(),
                },
                Err(legacy_err) => {
                    // Fallback: maybe it was a valid Go cache but marked incorrectly.
                    if let Ok(v) = serde_json::from_slice::<Cache>(&cache_binary) {
                        v
                    } else {
                        // Go parity: delete broken cache file on decode failure.
                        let _ = std::fs::remove_file(path);
                        return Err(legacy_err.into());
                    }
                }
            },
        };

        // Restore traffic stats per endpoint
        for (endpoint_tag, endpoint_cache) in cache.endpoints {
            let Some(ctx) = self.endpoints.get(&endpoint_tag) else {
                continue;
            };

            // Restore per-user traffic snapshot.
            let mut all_users: HashSet<String> = HashSet::new();
            all_users.extend(endpoint_cache.user_uplink.keys().cloned());
            all_users.extend(endpoint_cache.user_downlink.keys().cloned());
            all_users.extend(endpoint_cache.user_uplink_packets.keys().cloned());
            all_users.extend(endpoint_cache.user_downlink_packets.keys().cloned());
            all_users.extend(endpoint_cache.user_tcp_sessions.keys().cloned());
            all_users.extend(endpoint_cache.user_udp_sessions.keys().cloned());
            all_users.extend(endpoint_cache.users.keys().cloned());

            for username in all_users {
                let uplink = endpoint_cache.user_uplink.get(&username).copied().unwrap_or(0);
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
                let tcp_sessions = endpoint_cache
                    .user_tcp_sessions
                    .get(&username)
                    .copied()
                    .unwrap_or(0);
                let udp_sessions = endpoint_cache
                    .user_udp_sessions
                    .get(&username)
                    .copied()
                    .unwrap_or(0);

                if uplink != 0 || uplink_packets != 0 {
                    ctx.traffic_manager
                        .record_uplink(&username, uplink, uplink_packets);
                }
                if downlink != 0 || downlink_packets != 0 {
                    ctx.traffic_manager
                        .record_downlink(&username, downlink, downlink_packets);
                }
                if tcp_sessions != 0 {
                    ctx.traffic_manager
                        .increment_tcp_sessions(&username, tcp_sessions);
                }
                if udp_sessions != 0 {
                    ctx.traffic_manager
                        .increment_udp_sessions(&username, udp_sessions);
                }
            }

            // Restore users map (push to inbound; do not prune traffic, Go parity).
            if !endpoint_cache.users.is_empty() {
                let users_map: HashMap<String, String> =
                    endpoint_cache.users.into_iter().collect();
                let _ = ctx.user_manager.set_users(users_map);
            }
        }

        *self.last_saved_cache.lock() = cache_binary;

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

        let cache_binary = self.encode_cache_json()?;
        {
            let mut guard = self.last_saved_cache.lock();
            if *guard == cache_binary {
                return Ok(());
            }
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, &cache_binary)?;
            *guard = cache_binary;
        }

        tracing::debug!(service = "ssm-api", path = %path.display(), "Saved cache successfully");
        Ok(())
    }

    fn encode_cache_json(&self) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let mut endpoints = BTreeMap::new();
        for (endpoint, ctx) in &self.endpoints {
            let mut endpoint_cache = EndpointCache::default();

            // Global stats.
            let global = ctx.traffic_manager.read_global(false);
            endpoint_cache.global_uplink = global.uplink_bytes;
            endpoint_cache.global_downlink = global.downlink_bytes;
            endpoint_cache.global_uplink_packets = global.uplink_packets;
            endpoint_cache.global_downlink_packets = global.downlink_packets;
            endpoint_cache.global_tcp_sessions = global.tcp_sessions;
            endpoint_cache.global_udp_sessions = global.udp_sessions;

            // User stats + users map.
            for mut user in ctx.user_manager.list() {
                ctx.traffic_manager.read_user(&mut user, false);
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
                if user.tcp_sessions > 0 {
                    endpoint_cache
                        .user_tcp_sessions
                        .insert(username.clone(), user.tcp_sessions);
                }
                if user.udp_sessions > 0 {
                    endpoint_cache
                        .user_udp_sessions
                        .insert(username.clone(), user.udp_sessions);
                }

                if let Some(ref pwd) = user.password {
                    if !pwd.is_empty() {
                        endpoint_cache.users.insert(username, pwd.clone());
                    }
                }
            }

            endpoints.insert(endpoint.clone(), endpoint_cache);
        }

        let cache = Cache { endpoints };
        Ok(serde_json::to_vec_pretty(&cache)?)
    }

    /// Create the Axum router with all API endpoints.
    /// Includes per-endpoint nested routes:
    /// - `{endpoint}/server/v1/...` (Go parity for `servers` keys)
    fn create_router(&self) -> Router {
        let mut router = Router::new();
        for (endpoint, ctx) in &self.endpoints {
            let state = api::ApiState {
                user_manager: ctx.user_manager.clone(),
                traffic_manager: ctx.traffic_manager.clone(),
            };
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

    /// Back-compat helper: pick an endpoint context ("/" preferred) for callers that
    /// still assume a single manager exists.
    fn primary_endpoint(&self) -> &EndpointCtx {
        if let Some(ctx) = self.endpoints.get("/") {
            ctx
        } else {
            self.endpoints
                .values()
                .next()
                .expect("ssm-api: endpoints non-empty")
        }
    }

    /// Back-compat: return a UserManager for the primary endpoint.
    pub fn user_manager(&self) -> Arc<UserManager> {
        self.primary_endpoint().user_manager.clone()
    }

    /// Back-compat: return a TrafficManager for the primary endpoint.
    pub fn traffic_manager(&self) -> Arc<TrafficManager> {
        self.primary_endpoint().traffic_manager.clone()
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

                // Spawn periodic cache saver (Go parity: 1 minute).
                if self.cache_path.is_some() {
                    let endpoints = self.endpoints.clone();
                    let cache_path = self.cache_path.clone();
                    let last_saved_cache = self.last_saved_cache.clone();
                    let handle = tokio::spawn(async move {
                        let mut ticker = tokio::time::interval(Duration::from_secs(60));
                        // Go parity: first tick fires after 1 minute (not immediately).
                        ticker.tick().await;
                        loop {
                            ticker.tick().await;
                            let Some(path) = &cache_path else {
                                continue;
                            };
                            let cache_binary = {
                                // Encode without holding the mutex while doing IO.
                                let mut endpoints_cache = BTreeMap::new();
                                for (endpoint, ctx) in &endpoints {
                                    let mut endpoint_cache = EndpointCache::default();
                                    let global = ctx.traffic_manager.read_global(false);
                                    endpoint_cache.global_uplink = global.uplink_bytes;
                                    endpoint_cache.global_downlink = global.downlink_bytes;
                                    endpoint_cache.global_uplink_packets = global.uplink_packets;
                                    endpoint_cache.global_downlink_packets = global.downlink_packets;
                                    endpoint_cache.global_tcp_sessions = global.tcp_sessions;
                                    endpoint_cache.global_udp_sessions = global.udp_sessions;
                                    for mut user in ctx.user_manager.list() {
                                        ctx.traffic_manager.read_user(&mut user, false);
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
                                        if user.tcp_sessions > 0 {
                                            endpoint_cache
                                                .user_tcp_sessions
                                                .insert(username.clone(), user.tcp_sessions);
                                        }
                                        if user.udp_sessions > 0 {
                                            endpoint_cache
                                                .user_udp_sessions
                                                .insert(username.clone(), user.udp_sessions);
                                        }
                                        if let Some(ref pwd) = user.password {
                                            if !pwd.is_empty() {
                                                endpoint_cache.users.insert(username, pwd.clone());
                                            }
                                        }
                                    }
                                    endpoints_cache.insert(endpoint.clone(), endpoint_cache);
                                }
                                serde_json::to_vec_pretty(&Cache {
                                    endpoints: endpoints_cache,
                                })
                            };

                            let cache_binary = match cache_binary {
                                Ok(v) => v,
                                Err(e) => {
                                    tracing::error!(service = "ssm-api", error=%e, "Failed to encode cache");
                                    continue;
                                }
                            };

                            {
                                let mut guard = last_saved_cache.lock();
                                if *guard == cache_binary {
                                    continue;
                                }
                                if let Some(parent) = path.parent() {
                                    if let Err(e) = std::fs::create_dir_all(parent) {
                                        tracing::error!(service = "ssm-api", error=%e, "Failed to create cache dir");
                                        continue;
                                    }
                                }
                                if let Err(e) = std::fs::write(path, &cache_binary) {
                                    tracing::error!(service = "ssm-api", error=%e, "Failed to write cache");
                                    continue;
                                }
                                *guard = cache_binary;
                            }
                        }
                    });
                    *self.save_task.lock() = Some(handle);
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
                    let tls_config_res = if let (Some(cert_path), Some(key_path)) =
                        (&tls_cert_path, &tls_key_path)
                    {
                        Some(
                            axum_server::tls_rustls::RustlsConfig::from_pem_file(
                                cert_path, key_path,
                            )
                            .await,
                        )
                    } else if let (Some(cert_pem), Some(key_pem)) = (&tls_cert_pem, &tls_key_pem) {
                        Some(
                            axum_server::tls_rustls::RustlsConfig::from_pem(
                                cert_pem.clone(),
                                key_pem.clone(),
                            )
                            .await,
                        )
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

        // Stop periodic cache saver (best-effort).
        if let Some(handle) = self.save_task.lock().take() {
            handle.abort();
        }

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
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct DummyManagedServer {
        tag: String,
        tracker_set: AtomicUsize,
        update_calls: AtomicUsize,
    }

    impl super::super::ManagedSSMServer for DummyManagedServer {
        fn set_tracker(&self, _tracker: Arc<dyn super::super::TrafficTracker>) {
            self.tracker_set.fetch_add(1, Ordering::Relaxed);
        }

        fn tag(&self) -> &str {
            &self.tag
        }

        fn inbound_type(&self) -> &str {
            "shadowsocks"
        }

        fn update_users(&self, _users: Vec<String>, _passwords: Vec<String>) -> Result<(), String> {
            self.update_calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    fn create_test_ir() -> (ServiceIR, u16) {
        let port = 51000 + (fastrand::u16(0..1000));
        let mut servers = HashMap::new();
        servers.insert("/".to_string(), "ss-in".to_string());

        (
            ServiceIR {
            ty: ServiceType::Ssmapi,
            tag: Some("test-ssmapi".to_string()),
            listen: Some("127.0.0.1".to_string()),
            listen_port: Some(port),
            servers: Some(servers),
            ..Default::default()
            },
            port,
        )
    }

    #[test]
    fn test_service_creation() {
        let srv = Arc::new(DummyManagedServer {
            tag: "ss-in".to_string(),
            tracker_set: AtomicUsize::new(0),
            update_calls: AtomicUsize::new(0),
        });
        let srv_dyn: Arc<dyn super::super::ManagedSSMServer> = srv.clone();
        registry::register_managed_ssm_server("ss-in", Arc::downgrade(&srv_dyn));

        let (ir, port) = create_test_ir();
        let ctx = ServiceContext::default();

        let service = SsmapiService::from_ir(&ir, &ctx).expect("Failed to create service");

        assert_eq!(service.service_type(), "ssm-api");
        assert_eq!(service.tag(), "test-ssmapi");
        assert_eq!(service.listen_addr.port(), port);
        assert_eq!(service.user_manager().len(), 0);
        assert_eq!(srv.tracker_set.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_builder_function() {
        let srv = Arc::new(DummyManagedServer {
            tag: "ss-in".to_string(),
            tracker_set: AtomicUsize::new(0),
            update_calls: AtomicUsize::new(0),
        });
        let srv_dyn: Arc<dyn super::super::ManagedSSMServer> = srv.clone();
        registry::register_managed_ssm_server("ss-in", Arc::downgrade(&srv_dyn));

        let (ir, _port) = create_test_ir();
        let ctx = ServiceContext::default();

        let service = build_ssmapi_service(&ir, &ctx);
        assert!(service.is_some());

        let service = service.unwrap();
        assert_eq!(service.service_type(), "ssm-api");
    }

    #[test]
    fn test_create_router_does_not_panic() {
        let srv = Arc::new(DummyManagedServer {
            tag: "ss-in".to_string(),
            tracker_set: AtomicUsize::new(0),
            update_calls: AtomicUsize::new(0),
        });
        let srv_dyn: Arc<dyn super::super::ManagedSSMServer> = srv.clone();
        registry::register_managed_ssm_server("ss-in", Arc::downgrade(&srv_dyn));

        let (ir, _port) = create_test_ir();
        let ctx = ServiceContext::default();
        let service = SsmapiService::from_ir(&ir, &ctx).expect("Failed to create service");

        let _router = service.create_router();
    }

    #[test]
    fn test_cache_write_go_format_keys() {
        let srv = Arc::new(DummyManagedServer {
            tag: "ss-in".to_string(),
            tracker_set: AtomicUsize::new(0),
            update_calls: AtomicUsize::new(0),
        });
        let srv_dyn: Arc<dyn super::super::ManagedSSMServer> = srv.clone();
        registry::register_managed_ssm_server("ss-in", Arc::downgrade(&srv_dyn));

        let temp = tempfile::tempdir().unwrap();
        let cache_path = temp.path().join("ssmapi-cache.json");

        let (mut ir, _port) = create_test_ir();
        ir.cache_path = Some(cache_path.to_string_lossy().to_string());

        let ctx = ServiceContext::default();
        let service = SsmapiService::from_ir(&ir, &ctx).expect("Failed to create service");

        service
            .user_manager()
            .add("alice".to_string(), "pw".to_string())
            .unwrap();
        service.traffic_manager().record_uplink("alice", 123, 1);

        service.save_cache().unwrap();

        let json = std::fs::read_to_string(cache_path).unwrap();
        assert!(json.contains("\"global_uplink\""));
        assert!(json.contains("\"user_uplink\""));
        assert!(json.contains("\"users\""));
    }

    #[test]
    fn test_cache_read_legacy_then_write_go() {
        let srv = Arc::new(DummyManagedServer {
            tag: "ss-in".to_string(),
            tracker_set: AtomicUsize::new(0),
            update_calls: AtomicUsize::new(0),
        });
        let srv_dyn: Arc<dyn super::super::ManagedSSMServer> = srv.clone();
        registry::register_managed_ssm_server("ss-in", Arc::downgrade(&srv_dyn));

        let temp = tempfile::tempdir().unwrap();
        let cache_path = temp.path().join("ssmapi-cache.json");

        // Legacy (camelCase) cache payload.
        let legacy = serde_json::json!({
            "endpoints": {
                "/": {
                    "userUplink": { "alice": 10 },
                    "users": { "alice": "pw" }
                }
            }
        });
        std::fs::write(&cache_path, serde_json::to_vec_pretty(&legacy).unwrap()).unwrap();

        let (mut ir, _port) = create_test_ir();
        ir.cache_path = Some(cache_path.to_string_lossy().to_string());

        let ctx = ServiceContext::default();
        let service = SsmapiService::from_ir(&ir, &ctx).expect("Failed to create service");

        service.load_cache().unwrap();

        assert!(service.user_manager().contains("alice"));
        let mut u = crate::services::ssmapi::user::UserObject::new("alice".to_string(), None);
        service.traffic_manager().read_user(&mut u, false);
        assert_eq!(u.uplink_bytes, 10);

        service.save_cache().unwrap();
        let json = std::fs::read_to_string(cache_path).unwrap();
        assert!(json.contains("\"user_uplink\""));
        assert!(!json.contains("\"userUplink\""));
    }
}
