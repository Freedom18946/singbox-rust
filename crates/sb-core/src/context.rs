use crate::service::StartStage;
use dashmap::DashMap;
use once_cell::sync::Lazy;
use sb_config::ir::RouteIR;
use sb_platform::process::ProcessMatcher;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;

/// Trait for components that support lifecycle stages.
/// 支持生命周期阶段的组件的 trait。
pub trait Startable: Send + Sync {
    /// Start the component at a specific lifecycle stage.
    /// 在特定的生命周期阶段启动组件。
    fn start(&self, stage: StartStage) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;

    /// Close the component and release resources.
    /// 关闭组件并释放资源。
    fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
}

impl Startable for crate::inbound::InboundManager {
    fn start(&self, stage: StartStage) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::debug!(target: "sb_core::context", ?stage, "InboundManager stage");
        Ok(())
    }

    fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::debug!(target: "sb_core::context", "InboundManager closing");
        Ok(())
    }
}

impl Startable for crate::outbound::OutboundManager {
    fn start(&self, stage: StartStage) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::debug!(target: "sb_core::context", ?stage, "OutboundManager stage");
        Ok(())
    }

    fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::debug!(target: "sb_core::context", "OutboundManager closing");
        Ok(())
    }
}

impl Startable for crate::endpoint::EndpointManager {
    fn start(&self, stage: StartStage) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::debug!(target: "sb_core::context", ?stage, "EndpointManager stage");
        self.run_stage(stage)
    }

    fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::debug!(target: "sb_core::context", "EndpointManager closing");
        self.shutdown()
    }
}

impl Startable for crate::service::ServiceManager {
    fn start(&self, stage: StartStage) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::debug!(target: "sb_core::context", ?stage, "ServiceManager stage");
        Ok(())
    }

    fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::debug!(target: "sb_core::context", "ServiceManager closing");
        Ok(())
    }
}

/// Global runtime context containing registries and managers.
/// 全局运行时上下文，包含注册表和管理器。
#[derive(Clone, Debug)]
pub struct Context {
    pub network: Arc<NetworkManager>,
    pub connections: Arc<ConnectionManager>,
    pub task_monitor: Arc<TaskMonitor>,
    pub platform: Arc<PlatformInterface>,
    pub inbound_manager: Arc<crate::inbound::InboundManager>,
    pub outbound_manager: Arc<crate::outbound::OutboundManager>,
    pub endpoint_manager: Arc<crate::endpoint::EndpointManager>,
    pub service_manager: Arc<crate::service::ServiceManager>,
    pub cache_file: Option<Arc<dyn CacheFile>>,
    pub clash_server: Option<Arc<dyn ClashServer>>,
    pub v2ray_server: Option<Arc<dyn V2RayServer>>,
    pub ntp_service: Option<Arc<dyn NtpService>>,
    pub process_matcher: Option<Arc<ProcessMatcher>>,
    pub network_monitor: Arc<sb_platform::monitor::NetworkMonitor>,
}

/// Global registry exposing runtime managers for components that need late binding.
#[derive(Clone, Debug)]
pub struct ContextRegistry {
    pub network: Arc<NetworkManager>,
    pub connections: Arc<ConnectionManager>,
    pub task_monitor: Arc<TaskMonitor>,
    pub platform: Arc<PlatformInterface>,
    pub inbound_manager: Arc<crate::inbound::InboundManager>,
    pub outbound_manager: Arc<crate::outbound::OutboundManager>,
    pub endpoint_manager: Arc<crate::endpoint::EndpointManager>,
    pub service_manager: Arc<crate::service::ServiceManager>,
    pub cache_file: Option<Arc<dyn CacheFile>>,
    pub clash_server: Option<Arc<dyn ClashServer>>,
    pub v2ray_server: Option<Arc<dyn V2RayServer>>,
    pub ntp_service: Option<Arc<dyn NtpService>>,
    pub process_matcher: Option<Arc<ProcessMatcher>>,
    pub network_monitor: Arc<sb_platform::monitor::NetworkMonitor>,
}

impl From<&Context> for ContextRegistry {
    fn from(ctx: &Context) -> Self {
        Self {
            network: ctx.network.clone(),
            connections: ctx.connections.clone(),
            task_monitor: ctx.task_monitor.clone(),
            platform: ctx.platform.clone(),
            inbound_manager: ctx.inbound_manager.clone(),
            outbound_manager: ctx.outbound_manager.clone(),
            endpoint_manager: ctx.endpoint_manager.clone(),
            service_manager: ctx.service_manager.clone(),
            cache_file: ctx.cache_file.clone(),
            clash_server: ctx.clash_server.clone(),
            v2ray_server: ctx.v2ray_server.clone(),
            ntp_service: ctx.ntp_service.clone(),
            process_matcher: ctx.process_matcher.clone(),
            network_monitor: ctx.network_monitor.clone(),
        }
    }
}

static CONTEXT_REGISTRY: Lazy<std::sync::RwLock<Option<ContextRegistry>>> =
    Lazy::new(|| std::sync::RwLock::new(None));

/// Install the current runtime context into the global registry (used by late-bound components).
pub fn install_context_registry(ctx: &Context) {
    let mut guard = CONTEXT_REGISTRY.write().unwrap();
    *guard = Some(ContextRegistry::from(ctx));
}

/// Retrieve the current context registry snapshot, if installed.
pub fn context_registry() -> Option<ContextRegistry> {
    CONTEXT_REGISTRY.read().unwrap().clone()
}

impl Context {
    pub fn new() -> Self {
        Self {
            network: Arc::new(NetworkManager::new()),
            connections: Arc::new(ConnectionManager::new()),
            task_monitor: Arc::new(TaskMonitor::new()),
            platform: Arc::new(PlatformInterface::new()),
            inbound_manager: Arc::new(crate::inbound::InboundManager::new()),
            outbound_manager: Arc::new(crate::outbound::OutboundManager::new()),
            endpoint_manager: Arc::new(crate::endpoint::EndpointManager::new()),
            service_manager: Arc::new(crate::service::ServiceManager::new()),
            cache_file: None,
            clash_server: None,
            v2ray_server: None,
            ntp_service: None,
            process_matcher: match ProcessMatcher::new() {
                Ok(matcher) => Some(Arc::new(matcher)),
                Err(e) => {
                    tracing::warn!(target: "sb_core::context", error = %e, "failed to initialize process matcher");
                    None
                }
            },
            network_monitor: Arc::new(sb_platform::monitor::NetworkMonitor::new()),
        }
    }

    pub fn with_cache_file(mut self, cache_file: Arc<dyn CacheFile>) -> Self {
        self.cache_file = Some(cache_file);
        self
    }

    pub fn with_clash_server(mut self, clash_server: Arc<dyn ClashServer>) -> Self {
        self.clash_server = Some(clash_server);
        self
    }

    pub fn with_v2ray_server(mut self, v2ray_server: Arc<dyn V2RayServer>) -> Self {
        self.v2ray_server = Some(v2ray_server);
        self
    }

    pub fn with_ntp_service(mut self, ntp_service: Arc<dyn NtpService>) -> Self {
        self.ntp_service = Some(ntp_service);
        self
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

/// Network interface information.
/// 网络接口信息。
#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub addresses: Vec<IpAddr>,
    pub is_up: bool,
}

#[derive(Debug, Clone, Default)]
pub struct RouteOptions {
    pub find_process: bool,
    pub auto_detect_interface: bool,
    pub default_interface: Option<String>,
    pub mark: Option<u32>,
    pub default_resolver: Option<String>,
    pub network_strategy: Option<String>,
    pub default_outbound: Option<String>,
    pub final_outbound: Option<String>,
    pub default_network_type: Option<String>,
    pub default_fallback_network_type: Option<String>,
    pub default_fallback_delay: Option<String>,
    pub geoip_path: Option<String>,
    pub geoip_download_url: Option<String>,
    pub geoip_download_detour: Option<String>,
    pub geosite_path: Option<String>,
    pub geosite_download_url: Option<String>,
    pub geosite_download_detour: Option<String>,
    pub default_rule_set_download_detour: Option<String>,
}

/// Manages network interfaces and routing.
/// 管理网络接口和路由。
#[derive(Debug)]
pub struct NetworkManager {
    interfaces: Arc<RwLock<HashMap<String, NetworkInterface>>>,
    route_options: std::sync::RwLock<RouteOptions>,
}

impl NetworkManager {
    pub fn new() -> Self {
        Self {
            interfaces: Arc::new(RwLock::new(HashMap::new())),
            route_options: std::sync::RwLock::new(RouteOptions::default()),
        }
    }

    /// Register or update a network interface.
    pub async fn update_interface(&self, name: String, addresses: Vec<IpAddr>, is_up: bool) {
        let mut ifaces = self.interfaces.write().await;
        ifaces.insert(
            name.clone(),
            NetworkInterface {
                name,
                addresses,
                is_up,
            },
        );
    }

    /// Get all registered interfaces.
    pub async fn interfaces(&self) -> Vec<NetworkInterface> {
        self.interfaces.read().await.values().cloned().collect()
    }

    /// Get a specific interface by name.
    pub async fn get_interface(&self, name: &str) -> Option<NetworkInterface> {
        self.interfaces.read().await.get(name).cloned()
    }

    /// Apply route options from configuration for logging/runtime preference.
    pub fn apply_route_options(&self, route: &RouteIR) {
        let mut opts = self.route_options.write().unwrap();
        *opts = RouteOptions {
            find_process: route.find_process.unwrap_or(false),
            auto_detect_interface: route.auto_detect_interface.unwrap_or(false),
            default_interface: route.default_interface.clone(),
            mark: route.mark,
            default_resolver: route.default_resolver.clone(),
            network_strategy: route.network_strategy.clone(),
            default_outbound: route.default.clone(),
            final_outbound: route.final_outbound.clone(),
            default_network_type: route.default_network_type.clone(),
            default_fallback_network_type: route.default_fallback_network_type.clone(),
            default_fallback_delay: route.default_fallback_delay.clone(),
            geoip_path: route.geoip_path.clone(),
            geoip_download_url: route.geoip_download_url.clone(),
            geoip_download_detour: route.geoip_download_detour.clone(),
            geosite_path: route.geosite_path.clone(),
            geosite_download_url: route.geosite_download_url.clone(),
            geosite_download_detour: route.geosite_download_detour.clone(),
            default_rule_set_download_detour: route.default_rule_set_download_detour.clone(),
        };

        if opts.auto_detect_interface && opts.default_interface.is_none() {
            if let Some(iface) = sb_platform::system_proxy::get_default_interface_name() {
                tracing::info!("Auto-detected default interface: {}", iface);
                opts.default_interface = Some(iface);
            } else {
                tracing::warn!(
                    "Auto-detect interface enabled but failed to detect default interface"
                );
            }
        }
    }

    pub fn route_options(&self) -> RouteOptions {
        self.route_options.read().unwrap().clone()
    }
}

impl Default for NetworkManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Startable for NetworkManager {
    fn start(&self, stage: StartStage) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match stage {
            StartStage::Initialize => {
                tracing::debug!(target: "sb_core::context", "NetworkManager initializing");
                Ok(())
            }
            StartStage::Start => {
                tracing::info!(target: "sb_core::context", "NetworkManager starting - detecting network interfaces");
                let opts = self.route_options();
                if opts.auto_detect_interface
                    || opts.default_interface.is_some()
                    || opts.mark.is_some()
                    || opts.default_resolver.is_some()
                    || opts.network_strategy.is_some()
                    || opts.default_network_type.is_some()
                    || opts.default_fallback_network_type.is_some()
                    || opts.default_fallback_delay.is_some()
                {
                    tracing::info!(
                        target: "sb_core::context",
                        auto_detect = opts.auto_detect_interface,
                        default_interface = ?opts.default_interface,
                        mark = ?opts.mark,
                        default_resolver = ?opts.default_resolver,
                        network_strategy = ?opts.network_strategy,
                        default_network_type = ?opts.default_network_type,
                        default_fallback_network_type = ?opts.default_fallback_network_type,
                        default_fallback_delay = ?opts.default_fallback_delay,
                        "route/network options applied"
                    );
                }
                Ok(())
            }
            StartStage::PostStart | StartStage::Started => {
                tracing::debug!(target: "sb_core::context", "NetworkManager post-start complete");
                Ok(())
            }
        }
    }

    fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::debug!(target: "sb_core::context", "NetworkManager closing");
        Ok(())
    }
}

/// Connection tracking information.
/// 连接跟踪信息。
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub id: u64,
    pub source: String,
    pub destination: String,
    pub protocol: String,
    pub started_at: Instant,
}

/// Tracks active connections.
/// 跟踪活动连接。
#[derive(Debug)]
pub struct ConnectionManager {
    connections: Arc<DashMap<u64, ConnectionInfo>>,
    next_id: Arc<std::sync::atomic::AtomicU64>,
}

impl ConnectionManager {
    pub fn new() -> Self {
        Self {
            connections: Arc::new(DashMap::new()),
            next_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        }
    }

    /// Register a new connection and return its ID.
    pub fn register(&self, source: String, destination: String, protocol: String) -> u64 {
        let id = self
            .next_id
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let info = ConnectionInfo {
            id,
            source,
            destination,
            protocol,
            started_at: Instant::now(),
        };
        self.connections.insert(id, info);
        id
    }

    /// Remove a connection by ID.
    pub fn unregister(&self, id: u64) {
        self.connections.remove(&id);
    }

    /// Get total active connection count.
    pub fn count(&self) -> usize {
        self.connections.len()
    }

    /// Get connection info by ID.
    pub fn get(&self, id: u64) -> Option<ConnectionInfo> {
        self.connections.get(&id).map(|r| r.value().clone())
    }

    /// Get all active connections.
    pub fn all(&self) -> Vec<ConnectionInfo> {
        self.connections.iter().map(|r| r.value().clone()).collect()
    }
}

impl Default for ConnectionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Startable for ConnectionManager {
    fn start(&self, stage: StartStage) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match stage {
            StartStage::Initialize => {
                tracing::debug!(target: "sb_core::context", "ConnectionManager initializing");
                Ok(())
            }
            StartStage::Start => {
                tracing::info!(target: "sb_core::context", "ConnectionManager ready for connection tracking");
                Ok(())
            }
            StartStage::PostStart | StartStage::Started => {
                tracing::debug!(target: "sb_core::context", "ConnectionManager post-start complete");
                Ok(())
            }
        }
    }

    fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::debug!(target: "sb_core::context", "ConnectionManager closing");
        // Optionally clear connections or save state
        Ok(())
    }
}

/// Background task information.
/// 后台任务信息。
#[derive(Debug, Clone)]
pub struct TaskInfo {
    pub name: String,
    pub started_at: Instant,
    pub cancel_token: CancellationToken,
}

/// Manages background tasks.
/// 管理后台任务。
#[derive(Debug)]
pub struct TaskMonitor {
    tasks: Arc<DashMap<String, TaskInfo>>,
}

impl TaskMonitor {
    pub fn new() -> Self {
        Self {
            tasks: Arc::new(DashMap::new()),
        }
    }

    /// Register a background task.
    pub fn register(&self, name: String) -> CancellationToken {
        let cancel_token = CancellationToken::new();
        let info = TaskInfo {
            name: name.clone(),
            started_at: Instant::now(),
            cancel_token: cancel_token.clone(),
        };
        self.tasks.insert(name, info);
        cancel_token
    }

    /// Cancel a task by name.
    pub fn cancel(&self, name: &str) {
        if let Some(task) = self.tasks.get(name) {
            task.cancel_token.cancel();
        }
    }

    /// Cancel all tasks.
    pub fn cancel_all(&self) {
        for task in self.tasks.iter() {
            task.cancel_token.cancel();
        }
    }

    /// Remove a task from tracking.
    pub fn unregister(&self, name: &str) {
        self.tasks.remove(name);
    }

    /// Get all active task names.
    pub fn active_tasks(&self) -> Vec<String> {
        self.tasks.iter().map(|r| r.key().clone()).collect()
    }

    /// Get task count.
    pub fn count(&self) -> usize {
        self.tasks.len()
    }
}

impl Default for TaskMonitor {
    fn default() -> Self {
        Self::new()
    }
}

impl Startable for TaskMonitor {
    fn start(&self, stage: StartStage) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match stage {
            StartStage::Initialize => {
                tracing::debug!(target: "sb_core::context", "TaskMonitor initializing");
                Ok(())
            }
            StartStage::Start => {
                tracing::info!(target: "sb_core::context", "TaskMonitor ready for task registration");
                Ok(())
            }
            StartStage::PostStart | StartStage::Started => {
                tracing::debug!(target: "sb_core::context", "TaskMonitor post-start complete");
                Ok(())
            }
        }
    }

    fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::debug!(target: "sb_core::context", "TaskMonitor closing - cancelling all tasks");
        self.cancel_all();
        Ok(())
    }
}

/// Platform capabilities and information.
/// 平台能力和信息。
#[derive(Debug, Clone)]
pub struct PlatformInfo {
    pub os: String,
    pub arch: String,
    pub has_tun: bool,
    pub has_system_proxy: bool,
}

/// Provides platform-specific functionality.
/// 提供平台特定功能。
#[derive(Debug)]
pub struct PlatformInterface {
    info: PlatformInfo,
}

impl PlatformInterface {
    pub fn new() -> Self {
        Self {
            info: Self::detect_platform(),
        }
    }

    /// Detect platform capabilities.
    fn detect_platform() -> PlatformInfo {
        let os = std::env::consts::OS.to_string();
        let arch = std::env::consts::ARCH.to_string();

        // Detect TUN support based on platform
        let has_tun = matches!(os.as_str(), "linux" | "macos" | "windows");

        // Detect system proxy support
        let has_system_proxy = matches!(os.as_str(), "macos" | "linux" | "windows");

        PlatformInfo {
            os,
            arch,
            has_tun,
            has_system_proxy,
        }
    }

    /// Get platform information.
    pub fn info(&self) -> &PlatformInfo {
        &self.info
    }

    /// Check if TUN is supported on this platform.
    pub fn supports_tun(&self) -> bool {
        self.info.has_tun
    }

    /// Check if system proxy is supported on this platform.
    pub fn supports_system_proxy(&self) -> bool {
        self.info.has_system_proxy
    }
}

impl Default for PlatformInterface {
    fn default() -> Self {
        Self::new()
    }
}

impl Startable for PlatformInterface {
    fn start(&self, stage: StartStage) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match stage {
            StartStage::Initialize => {
                tracing::debug!(target: "sb_core::context", "PlatformInterface initializing");
                Ok(())
            }
            StartStage::Start => {
                tracing::info!(
                    target: "sb_core::context",
                    os = %self.info.os,
                    arch = %self.info.arch,
                    has_tun = self.info.has_tun,
                    has_system_proxy = self.info.has_system_proxy,
                    "PlatformInterface detected capabilities"
                );
                Ok(())
            }
            StartStage::PostStart | StartStage::Started => {
                tracing::debug!(target: "sb_core::context", "PlatformInterface post-start complete");
                Ok(())
            }
        }
    }

    fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        tracing::debug!(target: "sb_core::context", "PlatformInterface closing");
        Ok(())
    }
}

// Service traits
pub trait CacheFile: Send + Sync + std::fmt::Debug {}
pub trait ClashServer: Send + Sync + std::fmt::Debug {
    fn start(&self) -> anyhow::Result<()>;
    fn close(&self) -> anyhow::Result<()>;
    fn get_mode(&self) -> String;
}
pub trait V2RayServer: Send + Sync + std::fmt::Debug {
    fn start(&self) -> anyhow::Result<()>;
    fn close(&self) -> anyhow::Result<()>;
}
pub trait NtpService: Send + Sync + std::fmt::Debug {}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_network_manager() {
        let nm = NetworkManager::new();

        // Initially empty
        assert_eq!(nm.interfaces().await.len(), 0);

        // Add interface
        nm.update_interface(
            "eth0".to_string(),
            vec!["192.168.1.1".parse().unwrap()],
            true,
        )
        .await;

        assert_eq!(nm.interfaces().await.len(), 1);
        let iface = nm.get_interface("eth0").await.unwrap();
        assert_eq!(iface.name, "eth0");
        assert!(iface.is_up);
    }

    #[test]
    fn test_connection_manager() {
        let cm = ConnectionManager::new();

        // Initially empty
        assert_eq!(cm.count(), 0);

        // Register connection
        let id = cm.register(
            "127.0.0.1:1234".into(),
            "example.com:80".into(),
            "tcp".into(),
        );
        assert_eq!(cm.count(), 1);

        // Get connection
        let conn = cm.get(id).unwrap();
        assert_eq!(conn.protocol, "tcp");

        // Unregister
        cm.unregister(id);
        assert_eq!(cm.count(), 0);
    }

    #[test]
    fn test_task_monitor() {
        let tm = TaskMonitor::new();

        // Register task
        let token = tm.register("test_task".into());
        assert_eq!(tm.count(), 1);
        assert!(!token.is_cancelled());

        // Cancel task
        tm.cancel("test_task");
        assert!(token.is_cancelled());

        // Unregister
        tm.unregister("test_task");
        assert_eq!(tm.count(), 0);
    }

    #[test]
    fn test_platform_interface() {
        let pi = PlatformInterface::new();
        let info = pi.info();

        // Should detect OS and arch
        assert!(!info.os.is_empty());
        assert!(!info.arch.is_empty());

        // Platform capabilities should be consistent
        #[cfg(target_os = "linux")]
        assert!(pi.supports_tun());
        #[cfg(target_os = "macos")]
        assert!(pi.supports_system_proxy());
    }

    #[test]
    fn test_context_builder() {
        let ctx = Context::new();
        assert!(ctx.cache_file.is_none());
        assert!(ctx.clash_server.is_none());
        assert!(ctx.v2ray_server.is_none());
        assert!(ctx.ntp_service.is_none());
        // process_matcher might be Some or None depending on platform support
    }

    #[test]
    fn test_route_options_apply_and_read() {
        let nm = NetworkManager::new();
        let route = RouteIR {
            find_process: Some(true),
            auto_detect_interface: Some(true),
            default_interface: Some("eth0".into()),
            mark: Some(42),
            default_resolver: Some("dns-local".into()),
            network_strategy: Some("prefer_ipv6".into()),
            default: Some("direct".into()),
            final_outbound: Some("block".into()),
            default_network_type: Some("ipv4_only".into()),
            default_fallback_network_type: Some("ipv6_only".into()),
            default_fallback_delay: Some("250ms".into()),
            geoip_path: Some("geoip.db".into()),
            geoip_download_url: Some("http://geoip".into()),
            geoip_download_detour: Some("proxy".into()),
            geosite_path: Some("geosite.db".into()),
            geosite_download_url: Some("http://geosite".into()),
            geosite_download_detour: Some("direct".into()),
            default_rule_set_download_detour: Some("proxy".into()),
            ..Default::default()
        };

        nm.apply_route_options(&route);
        let opts = nm.route_options();

        assert!(opts.find_process);
        assert!(opts.auto_detect_interface);
        assert_eq!(opts.default_interface.as_deref(), Some("eth0"));
        assert_eq!(opts.mark, Some(42));
        assert_eq!(opts.default_resolver.as_deref(), Some("dns-local"));
        assert_eq!(opts.network_strategy.as_deref(), Some("prefer_ipv6"));
        assert_eq!(opts.default_outbound.as_deref(), Some("direct"));
        assert_eq!(opts.final_outbound.as_deref(), Some("block"));
        assert_eq!(opts.default_network_type.as_deref(), Some("ipv4_only"));
        assert_eq!(
            opts.default_fallback_network_type.as_deref(),
            Some("ipv6_only")
        );
        assert_eq!(opts.default_fallback_delay.as_deref(), Some("250ms"));
        assert_eq!(opts.geoip_path.as_deref(), Some("geoip.db"));
        assert_eq!(opts.geoip_download_url.as_deref(), Some("http://geoip"));
        assert_eq!(opts.geoip_download_detour.as_deref(), Some("proxy"));
        assert_eq!(opts.geosite_path.as_deref(), Some("geosite.db"));
        assert_eq!(opts.geosite_download_url.as_deref(), Some("http://geosite"));
        assert_eq!(opts.geosite_download_detour.as_deref(), Some("direct"));
        assert_eq!(
            opts.default_rule_set_download_detour.as_deref(),
            Some("proxy")
        );
    }
}
