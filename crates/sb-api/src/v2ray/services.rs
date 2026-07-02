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
        Err(Status::unimplemented(
            "V2Ray system statistics are not wired to runtime metrics",
        ))
    }
}

/// Handler service implementation for managing inbound/outbound proxies
/// 用于管理入站/出站代理的处理程序服务实现
///
/// Allows dynamic addition/removal/modification of inbounds and outbounds at runtime.
/// 允许在运行时动态添加/删除/修改入站和出站。
pub struct HandlerServiceImpl {
    inbound_manager: InboundManager,
    outbound_manager: OutboundManager,
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

        let inbound_config = req
            .inbound
            .ok_or_else(|| Status::invalid_argument("inbound field is required"))?;

        log::info!(
            "V2Ray API: Add inbound request for tag '{}'",
            inbound_config.tag
        );

        Err(Status::unimplemented(
            "V2Ray add_inbound requires runtime config parsing and is not implemented",
        ))
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

        Err(Status::unimplemented(
            "V2Ray alter_inbound requires runtime config parsing and is not implemented",
        ))
    }

    async fn add_outbound(
        &self,
        request: Request<AddOutboundRequest>,
    ) -> Result<Response<AddOutboundResponse>, Status> {
        let req = request.into_inner();

        let outbound_config = req
            .outbound
            .ok_or_else(|| Status::invalid_argument("outbound field is required"))?;

        log::info!(
            "V2Ray API: Add outbound request for tag '{}'",
            outbound_config.tag
        );

        Err(Status::unimplemented(
            "V2Ray add_outbound requires runtime config parsing and is not implemented",
        ))
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

        Err(Status::unimplemented(
            "V2Ray alter_outbound requires runtime config parsing and is not implemented",
        ))
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

        let routing_ctx = req.routing_context.unwrap_or_default();

        if routing_ctx.outbound_tag.is_empty() {
            return Err(Status::failed_precondition(
                "routing outbound_tag is empty; implicit direct fallback is disabled; provide outbound_tag explicitly",
            ));
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

        Err(Status::unimplemented(
            "V2Ray logger restart is not wired to the runtime logging backend",
        ))
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

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::Code;

    #[tokio::test]
    async fn get_sys_stats_is_explicitly_unimplemented() {
        let service = StatsServiceImpl::new();
        let err = service
            .get_sys_stats(Request::new(SysStatsRequest {}))
            .await
            .expect_err("mock system stats must not be returned");

        assert_eq!(err.code(), Code::Unimplemented);
    }

    #[tokio::test]
    async fn handler_add_paths_are_explicitly_unimplemented() {
        let service = HandlerServiceImpl::new();
        let inbound = crate::v2ray::generated::v2ray::core::InboundHandlerConfig {
            tag: "inbound-a".to_string(),
            receiver_settings: None,
            proxy_settings: None,
        };
        let outbound = crate::v2ray::generated::v2ray::core::OutboundHandlerConfig {
            tag: "outbound-a".to_string(),
            sender_settings: None,
            proxy_settings: None,
            proxy_tag: String::new(),
        };

        let inbound_err = service
            .add_inbound(Request::new(AddInboundRequest {
                inbound: Some(inbound),
            }))
            .await
            .expect_err("stub inbound must not be registered");
        let outbound_err = service
            .add_outbound(Request::new(AddOutboundRequest {
                outbound: Some(outbound),
            }))
            .await
            .expect_err("direct outbound clone must not be registered");

        assert_eq!(inbound_err.code(), Code::Unimplemented);
        assert_eq!(outbound_err.code(), Code::Unimplemented);
    }

    #[tokio::test]
    async fn restart_logger_is_explicitly_unimplemented() {
        let service = LoggerServiceImpl::new();
        let err = service
            .restart_logger(Request::new(RestartLoggerRequest {}))
            .await
            .expect_err("logger restart must not report fake success");

        assert_eq!(err.code(), Code::Unimplemented);
    }
}
