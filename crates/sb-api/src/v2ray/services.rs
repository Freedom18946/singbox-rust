//! V2Ray API gRPC service implementations

use crate::v2ray::generated::*;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::Stream;
use tonic::{Request, Response, Status};
use std::pin::Pin;
use std::task::{Context, Poll};

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
pub struct StatsServiceImpl {
    stats: Arc<Mutex<HashMap<String, i64>>>,
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

        let stats = self
            .stats
            .lock()
            .map_err(|_| Status::internal("Failed to acquire stats lock"))?;

        let stat_value = stats.get(&req.name).copied().unwrap_or(0);

        // TODO: Implement reset functionality if req.reset is true

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
pub struct HandlerServiceImpl {
    // In production, this would hold references to actual proxy managers
}

impl HandlerServiceImpl {
    pub fn new() -> Self {
        Self {}
    }
}

#[tonic::async_trait]
impl HandlerService for HandlerServiceImpl {
    async fn add_inbound(
        &self,
        request: Request<AddInboundRequest>,
    ) -> Result<Response<AddInboundResponse>, Status> {
        let _req = request.into_inner();

        // TODO: Integrate with actual inbound manager
        log::info!("V2Ray API: Add inbound request received");

        Ok(Response::new(AddInboundResponse {}))
    }

    async fn remove_inbound(
        &self,
        request: Request<RemoveInboundRequest>,
    ) -> Result<Response<RemoveInboundResponse>, Status> {
        let req = request.into_inner();

        // TODO: Integrate with actual inbound manager
        log::info!("V2Ray API: Remove inbound '{}' request received", req.tag);

        Ok(Response::new(RemoveInboundResponse {}))
    }

    async fn alter_inbound(
        &self,
        request: Request<AlterInboundRequest>,
    ) -> Result<Response<AlterInboundResponse>, Status> {
        let req = request.into_inner();

        // TODO: Integrate with actual inbound manager
        log::info!("V2Ray API: Alter inbound '{}' request received", req.tag);

        Ok(Response::new(AlterInboundResponse {}))
    }

    async fn add_outbound(
        &self,
        request: Request<AddOutboundRequest>,
    ) -> Result<Response<AddOutboundResponse>, Status> {
        let _req = request.into_inner();

        // TODO: Integrate with actual outbound manager
        log::info!("V2Ray API: Add outbound request received");

        Ok(Response::new(AddOutboundResponse {}))
    }

    async fn remove_outbound(
        &self,
        request: Request<RemoveOutboundRequest>,
    ) -> Result<Response<RemoveOutboundResponse>, Status> {
        let req = request.into_inner();

        // TODO: Integrate with actual outbound manager
        log::info!("V2Ray API: Remove outbound '{}' request received", req.tag);

        Ok(Response::new(RemoveOutboundResponse {}))
    }

    async fn alter_outbound(
        &self,
        request: Request<AlterOutboundRequest>,
    ) -> Result<Response<AlterOutboundResponse>, Status> {
        let req = request.into_inner();

        // TODO: Integrate with actual outbound manager
        log::info!("V2Ray API: Alter outbound '{}' request received", req.tag);

        Ok(Response::new(AlterOutboundResponse {}))
    }
}

/// Router service implementation for routing management
pub struct RouterServiceImpl {
    routing_broadcast: broadcast::Sender<RoutingContext>,
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

        // TODO: Integrate with actual router for route testing
        let mut routing_ctx = req.routing_context.unwrap_or_default();

        // Mock route testing - set a default outbound
        routing_ctx.outbound_tag = "direct".to_string();

        if req.publish_result {
            self.broadcast_routing_update(routing_ctx.clone());
        }

        Ok(Response::new(routing_ctx))
    }
}

/// Logger service implementation for log management
pub struct LoggerServiceImpl {
    log_broadcast: broadcast::Sender<LogEntry>,
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
        // TODO: Integrate with actual logging system restart
        log::info!("V2Ray API: Logger restart requested");

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
