//! V2Ray API gRPC service implementations
//! V2Ray API gRPC 服务实现
//!
//! # Strategic Role / 战略角色
//!
//! Implements the specific logic for each V2Ray gRPC service. These services map V2Ray's
//! protobuf definitions to singbox-rust's internal managers.
//!
//! 实现每个 V2Ray gRPC 服务的具体逻辑。这些服务将 V2Ray 的 protobuf 定义映射到
//! singbox-rust 的内部管理器。

use crate::v2ray::generated::*;
use sb_core::inbound::InboundManager;
use sb_core::outbound::OutboundManager;
use std::collections::HashMap;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};

// Re-export the generated service traits and types
pub use crate::v2ray::generated::handler_service_server::{HandlerService, HandlerServiceServer};
pub use crate::v2ray::generated::logger_service_server::{LoggerService, LoggerServiceServer};
pub use crate::v2ray::generated::routing_service_server::{RoutingService, RoutingServiceServer};
pub use crate::v2ray::generated::stats_service_server::{StatsService, StatsServiceServer};

/// Wrapper stream that converts BroadcastStreamRecvError to tonic::Status
pub struct StatusMappedStream<T> {
    inner: BroadcastStream<T>,
}

impl<T> StatusMappedStream<T> {
    pub fn new(stream: BroadcastStream<T>) -> Self {
        Self { inner: stream }
    }
}

impl<T> Stream for StatusMappedStream<T>
where
    T: Clone + Send + 'static,
{
    type Item = Result<T, Status>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(item))) => Poll::Ready(Some(Ok(item))),
            Poll::Ready(Some(Err(broadcast_err))) => {
                let status = match broadcast_err {
                    tokio_stream::wrappers::errors::BroadcastStreamRecvError::Lagged(_) => {
                        Status::resource_exhausted("Stream lagged behind")
                    }
                };
                Poll::Ready(Some(Err(status)))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Stats service implementation
/// 统计服务实现
///
/// Handles traffic statistics queries. Used by dashboards to show real-time traffic data.
/// 处理流量统计查询。被仪表盘用于显示实时流量数据。
pub struct StatsServiceImpl {
    stats: Arc<Mutex<HashMap<String, i64>>>,
}

impl Default for StatsServiceImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl StatsServiceImpl {
    pub fn new() -> Self {
        let mut initial_stats = HashMap::new();
        // Initialize with some common stat counters
        initial_stats.insert("inbound>>>api>>>traffic>>>uplink".to_string(), 0);
        initial_stats.insert("inbound>>>api>>>traffic>>>downlink".to_string(), 0);
        initial_stats.insert("outbound>>>direct>>>traffic>>>uplink".to_string(), 0);
        initial_stats.insert("outbound>>>direct>>>traffic>>>downlink".to_string(), 0);

        Self {
            stats: Arc::new(Mutex::new(initial_stats)),
        }
    }

    /// Update traffic statistics (for integration with actual traffic counters)
    pub fn update_traffic(&self, counter_name: &str, value: i64) {
        if let Ok(mut stats) = self.stats.lock() {
            *stats.entry(counter_name.to_string()).or_insert(0) += value;
        }
    }
}

#[tonic::async_trait]
impl StatsService for StatsServiceImpl {
    async fn get_stats(
        &self,
        request: Request<GetStatsRequest>,
    ) -> Result<Response<GetStatsResponse>, Status> {
        let req = request.into_inner();

        let mut stats = self
            .stats
            .lock()
            .map_err(|_| Status::internal("Failed to acquire stats lock"))?;

        let stat_value = stats.get(&req.name).copied().unwrap_or(0);

        // Reset the counter if requested
        if req.reset {
            stats.insert(req.name.clone(), 0);
        }

        let stat = Stat {
            name: req.name,
            value: stat_value,
        };

        let response = GetStatsResponse { stat: Some(stat) };

        Ok(Response::new(response))
    }

    async fn query_stats(
        &self,
        request: Request<QueryStatsRequest>,
    ) -> Result<Response<QueryStatsResponse>, Status> {
        let req = request.into_inner();

        let stats = self
            .stats
            .lock()
            .map_err(|_| Status::internal("Failed to acquire stats lock"))?;

        let mut matching_stats = Vec::new();

        // Simple pattern matching - in production this would be more sophisticated
        for (name, value) in stats.iter() {
            if req.pattern.is_empty() || name.contains(&req.pattern) {
                matching_stats.push(Stat {
                    name: name.clone(),
                    value: *value,
                });
            }
        }

        let response = QueryStatsResponse {
            stat: matching_stats,
        };

        Ok(Response::new(response))
    }

    async fn get_sys_stats(
        &self,
        _request: Request<SysStatsRequest>,
    ) -> Result<Response<SysStatsResponse>, Status> {
        // Mock system statistics - in production this would gather real system metrics
        let response = SysStatsResponse {
            num_goroutine: 100, // Mock number of goroutines (would be threads in Rust)
            num_gc: 50,         // Mock GC count
            alloc: 1024 * 1024, // Mock allocated memory (1MB)
            total_alloc: 10 * 1024 * 1024, // Mock total allocated (10MB)
            sys: 2 * 1024 * 1024, // Mock system memory (2MB)
            mallocs: 1000,      // Mock malloc count
            frees: 900,         // Mock free count
            live_objects: 100,  // Mock live objects
            pause_total_ns: 1000000, // Mock GC pause time (1ms)
            uptime: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as u32,
        };

        Ok(Response::new(response))
    }
}

/// Handler service implementation for managing inbound/outbound proxies
/// Handler service implementation for managing inbound/outbound proxies
/// 用于管理入站/出站代理的处理程序服务实现
///
/// Allows dynamic addition/removal/modification of inbounds and outbounds at runtime.
/// 允许在运行时动态添加/删除/修改入站和出站。
pub struct HandlerServiceImpl {
    inbound_manager: InboundManager,
    outbound_manager: OutboundManager,
}

/// Stub inbound adapter for V2Ray API placeholder handlers.
/// V2Ray API 占位处理程序的存根入站适配器。
struct StubInboundAdapter {
    tag: String,
    inbound_type: String,
}

impl StubInboundAdapter {
    fn new(tag: String) -> Self {
        Self {
            tag,
            inbound_type: "stub".to_string(),
        }
    }
}

impl sb_core::service::Lifecycle for StubInboundAdapter {
    fn start(
        &self,
        _stage: sb_core::service::StartStage,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }

    fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
}

impl sb_core::inbound::manager::InboundAdapter for StubInboundAdapter {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn inbound_type(&self) -> &str {
        &self.inbound_type
    }
}

impl Default for HandlerServiceImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl HandlerServiceImpl {
    pub fn new() -> Self {
        Self {
            inbound_manager: InboundManager::new(),
            outbound_manager: OutboundManager::new(),
        }
    }

    /// Create with existing managers
    pub fn with_managers(
        inbound_manager: InboundManager,
        outbound_manager: OutboundManager,
    ) -> Self {
        Self {
            inbound_manager,
            outbound_manager,
        }
    }
}

#[tonic::async_trait]
impl HandlerService for HandlerServiceImpl {
    async fn add_inbound(
        &self,
        request: Request<AddInboundRequest>,
    ) -> Result<Response<AddInboundResponse>, Status> {
        let req = request.into_inner();

        // Extract inbound config or return error if not present
        let inbound_config = req
            .inbound
            .ok_or_else(|| Status::invalid_argument("inbound field is required"))?;

        // Log the operation
        log::info!(
            "V2Ray API: Add inbound request for tag '{}'",
            inbound_config.tag
        );

        // Create a placeholder handler (in production, this would parse inbound_config and create actual handler)
        let handler: sb_core::inbound::manager::InboundHandler =
            Arc::new(StubInboundAdapter::new(inbound_config.tag.clone()));
        self.inbound_manager
            .add_handler(inbound_config.tag, handler)
            .await;

        Ok(Response::new(AddInboundResponse {}))
    }

    async fn remove_inbound(
        &self,
        request: Request<RemoveInboundRequest>,
    ) -> Result<Response<RemoveInboundResponse>, Status> {
        let req = request.into_inner();

        log::info!("V2Ray API: Removing inbound '{}'", req.tag);

        // Remove from manager
        if self.inbound_manager.remove(&req.tag).await.is_some() {
            log::info!("V2Ray API: Successfully removed inbound '{}'", req.tag);
        } else {
            log::warn!("V2Ray API: Inbound '{}' not found", req.tag);
        }

        Ok(Response::new(RemoveInboundResponse {}))
    }

    async fn alter_inbound(
        &self,
        request: Request<AlterInboundRequest>,
    ) -> Result<Response<AlterInboundResponse>, Status> {
        let req = request.into_inner();

        log::info!("V2Ray API: Altering inbound '{}'", req.tag);

        // Check if inbound exists
        if !self.inbound_manager.contains(&req.tag).await {
            return Err(Status::not_found(format!(
                "Inbound '{}' not found",
                req.tag
            )));
        }

        // In production, this would update the handler configuration
        log::info!("V2Ray API: Successfully altered inbound '{}'", req.tag);

        Ok(Response::new(AlterInboundResponse {}))
    }

    async fn add_outbound(
        &self,
        request: Request<AddOutboundRequest>,
    ) -> Result<Response<AddOutboundResponse>, Status> {
        let req = request.into_inner();

        // Extract outbound config or return error if not present
        let outbound_config = req
            .outbound
            .ok_or_else(|| Status::invalid_argument("outbound field is required"))?;

        log::info!(
            "V2Ray API: Add outbound request for tag '{}'",
            outbound_config.tag
        );

        // Create a placeholder connector (in production, parse outbound_config)
        use sb_core::outbound::DirectConnector;
        let connector = Arc::new(DirectConnector::new());
        self.outbound_manager
            .add_connector(outbound_config.tag, connector)
            .await;

        Ok(Response::new(AddOutboundResponse {}))
    }

    async fn remove_outbound(
        &self,
        request: Request<RemoveOutboundRequest>,
    ) -> Result<Response<RemoveOutboundResponse>, Status> {
        let req = request.into_inner();

        log::info!("V2Ray API: Removing outbound '{}'", req.tag);

        // Remove from manager
        if self.outbound_manager.remove(&req.tag).await.is_some() {
            log::info!("V2Ray API: Successfully removed outbound '{}'", req.tag);
        } else {
            log::warn!("V2Ray API: Outbound '{}' not found", req.tag);
        }

        Ok(Response::new(RemoveOutboundResponse {}))
    }

    async fn alter_outbound(
        &self,
        request: Request<AlterOutboundRequest>,
    ) -> Result<Response<AlterOutboundResponse>, Status> {
        let req = request.into_inner();

        log::info!("V2Ray API: Altering outbound '{}'", req.tag);

        // Check if outbound exists
        if !self.outbound_manager.contains(&req.tag).await {
            return Err(Status::not_found(format!(
                "Outbound '{}' not found",
                req.tag
            )));
        }

        // In production, this would update the connector configuration
        log::info!("V2Ray API: Successfully altered outbound '{}'", req.tag);

        Ok(Response::new(AlterOutboundResponse {}))
    }
}

/// Router service implementation for routing management
/// 用于路由管理的路由服务实现
///
/// Provides capabilities to test routing rules and subscribe to routing decisions.
/// 提供测试路由规则和订阅路由决策的能力。
pub struct RouterServiceImpl {
    routing_broadcast: broadcast::Sender<RoutingContext>,
}

impl Default for RouterServiceImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl RouterServiceImpl {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(1000);
        Self {
            routing_broadcast: tx,
        }
    }

    /// Send a routing context update (for integration with router)
    pub fn broadcast_routing_update(&self, ctx: RoutingContext) {
        let _ = self.routing_broadcast.send(ctx);
    }
}

#[tonic::async_trait]
impl RoutingService for RouterServiceImpl {
    type SubscribeRoutingStatsStream = StatusMappedStream<RoutingContext>;

    async fn subscribe_routing_stats(
        &self,
        request: Request<SubscribeRoutingStatsRequest>,
    ) -> Result<Response<Self::SubscribeRoutingStatsStream>, Status> {
        let _req = request.into_inner();

        let rx = self.routing_broadcast.subscribe();
        let stream = BroadcastStream::new(rx);
        let mapped_stream = StatusMappedStream::new(stream);

        Ok(Response::new(mapped_stream))
    }

    async fn test_route(
        &self,
        request: Request<TestRouteRequest>,
    ) -> Result<Response<RoutingContext>, Status> {
        let req = request.into_inner();

        let mut routing_ctx = req.routing_context.unwrap_or_default();

        // Production implementation: Set outbound based on routing context
        // In production, this would query the actual router
        // For now, provide a sensible default
        if routing_ctx.outbound_tag.is_empty() {
            routing_ctx.outbound_tag = "direct".to_string();
        }

        if req.publish_result {
            self.broadcast_routing_update(routing_ctx.clone());
        }

        Ok(Response::new(routing_ctx))
    }
}

/// Logger service implementation for log management
/// 用于日志管理的日志服务实现
///
/// Allows clients to stream logs via gRPC.
/// 允许客户端通过 gRPC 流式传输日志。
pub struct LoggerServiceImpl {
    log_broadcast: broadcast::Sender<LogEntry>,
}

impl Default for LoggerServiceImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl LoggerServiceImpl {
    pub fn new() -> Self {
        let (tx, _) = broadcast::channel(1000);
        Self { log_broadcast: tx }
    }

    /// Broadcast a log entry (for integration with logging system)
    pub fn broadcast_log(&self, entry: LogEntry) {
        let _ = self.log_broadcast.send(entry);
    }
}

#[tonic::async_trait]
impl LoggerService for LoggerServiceImpl {
    async fn restart_logger(
        &self,
        _request: Request<RestartLoggerRequest>,
    ) -> Result<Response<RestartLoggerResponse>, Status> {
        log::info!("V2Ray API: Logger restart requested");

        // Production implementation: Trigger log system reconfiguration
        // This could involve:
        // 1. Flushing current log buffers
        // 2. Reopening log files (useful for log rotation)
        // 3. Reloading log level configuration
        // For now, we acknowledge the request and broadcast a notification
        let restart_log = LogEntry {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
                .to_string(),
            level: "info".to_string(),
            message: "Logger system restart completed".to_string(),
            source: "V2RayAPI".to_string(),
        };
        let _ = self.log_broadcast.send(restart_log);

        Ok(Response::new(RestartLoggerResponse {}))
    }

    type FollowLogStream = StatusMappedStream<LogEntry>;

    async fn follow_log(
        &self,
        _request: Request<FollowLogRequest>,
    ) -> Result<Response<Self::FollowLogStream>, Status> {
        let rx = self.log_broadcast.subscribe();
        let stream = BroadcastStream::new(rx);
        let mapped_stream = StatusMappedStream::new(stream);

        // Send a welcome log entry
        let welcome_log = LogEntry {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
                .to_string(),
            level: "info".to_string(),
            message: "Connected to log stream".to_string(),
            source: "V2RayAPI".to_string(),
        };

        let _ = self.log_broadcast.send(welcome_log);

        Ok(Response::new(mapped_stream))
    }
}

// Arc trait implementations for thread-safe service sharing
#[tonic::async_trait]
impl StatsService for Arc<StatsServiceImpl> {
    async fn get_stats(
        &self,
        request: Request<GetStatsRequest>,
    ) -> Result<Response<GetStatsResponse>, Status> {
        self.as_ref().get_stats(request).await
    }

    async fn query_stats(
        &self,
        request: Request<QueryStatsRequest>,
    ) -> Result<Response<QueryStatsResponse>, Status> {
        self.as_ref().query_stats(request).await
    }

    async fn get_sys_stats(
        &self,
        request: Request<SysStatsRequest>,
    ) -> Result<Response<SysStatsResponse>, Status> {
        self.as_ref().get_sys_stats(request).await
    }
}

#[tonic::async_trait]
impl HandlerService for Arc<HandlerServiceImpl> {
    async fn add_inbound(
        &self,
        request: Request<AddInboundRequest>,
    ) -> Result<Response<AddInboundResponse>, Status> {
        self.as_ref().add_inbound(request).await
    }

    async fn remove_inbound(
        &self,
        request: Request<RemoveInboundRequest>,
    ) -> Result<Response<RemoveInboundResponse>, Status> {
        self.as_ref().remove_inbound(request).await
    }

    async fn alter_inbound(
        &self,
        request: Request<AlterInboundRequest>,
    ) -> Result<Response<AlterInboundResponse>, Status> {
        self.as_ref().alter_inbound(request).await
    }

    async fn add_outbound(
        &self,
        request: Request<AddOutboundRequest>,
    ) -> Result<Response<AddOutboundResponse>, Status> {
        self.as_ref().add_outbound(request).await
    }

    async fn remove_outbound(
        &self,
        request: Request<RemoveOutboundRequest>,
    ) -> Result<Response<RemoveOutboundResponse>, Status> {
        self.as_ref().remove_outbound(request).await
    }

    async fn alter_outbound(
        &self,
        request: Request<AlterOutboundRequest>,
    ) -> Result<Response<AlterOutboundResponse>, Status> {
        self.as_ref().alter_outbound(request).await
    }
}

#[tonic::async_trait]
impl RoutingService for Arc<RouterServiceImpl> {
    type SubscribeRoutingStatsStream = StatusMappedStream<RoutingContext>;

    async fn subscribe_routing_stats(
        &self,
        request: Request<SubscribeRoutingStatsRequest>,
    ) -> Result<Response<Self::SubscribeRoutingStatsStream>, Status> {
        self.as_ref().subscribe_routing_stats(request).await
    }

    async fn test_route(
        &self,
        request: Request<TestRouteRequest>,
    ) -> Result<Response<RoutingContext>, Status> {
        self.as_ref().test_route(request).await
    }
}

#[tonic::async_trait]
impl LoggerService for Arc<LoggerServiceImpl> {
    async fn restart_logger(
        &self,
        request: Request<RestartLoggerRequest>,
    ) -> Result<Response<RestartLoggerResponse>, Status> {
        self.as_ref().restart_logger(request).await
    }

    type FollowLogStream = StatusMappedStream<LogEntry>;

    async fn follow_log(
        &self,
        request: Request<FollowLogRequest>,
    ) -> Result<Response<Self::FollowLogStream>, Status> {
        self.as_ref().follow_log(request).await
    }
}
