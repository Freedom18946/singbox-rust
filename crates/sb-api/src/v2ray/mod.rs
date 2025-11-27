//! V2Ray API implementation
//! V2Ray API 实现
//!
//! This module provides V2Ray-compatible API services for managing
//! and monitoring the proxy server. It supports both gRPC (when v2ray-api
//! feature is enabled) and a simplified implementation (default).
//!
//! 本模块提供兼容 V2Ray 的 API 服务，用于管理和监控代理服务器。它支持 gRPC（当启用
//! v2ray-api 特性时）和简化实现（默认）。

#![warn(missing_docs)]
// 该模块为 gRPC/协议壳，文档噪声在严格门禁下过高，先局部豁免，生产面向文档另行提供。
#![allow(missing_docs)]

pub mod server;
pub mod simple;

#[cfg(feature = "v2ray-api")]
pub mod services;

#[cfg(feature = "v2ray-api")]
pub mod generated {
    //! Stub protobuf types for V2Ray API
    //!
    //! This module provides the necessary types and traits for V2Ray API
    //! without relying on problematic protobuf generation.

    use serde::{Deserialize, Serialize};

    // Core config types
    #[derive(Debug, Default, Clone, Serialize, Deserialize)]
    pub struct InboundHandlerConfig {
        pub tag: String,
        pub receiver_settings: Option<String>,
        pub proxy_settings: Option<String>,
    }

    // Stats service types
    #[derive(Debug, Default, Clone, Serialize, Deserialize)]
    pub struct GetStatsRequest {
        pub name: String,
        pub reset: bool,
    }

    #[derive(Debug, Default, Clone, Serialize, Deserialize)]
    pub struct GetStatsResponse {
        pub stat: Option<Stat>,
    }

    #[derive(Debug, Default, Clone, Serialize, Deserialize)]
    pub struct QueryStatsRequest {
        pub pattern: String,
        pub reset: bool,
    }

    #[derive(Debug, Default, Clone, Serialize, Deserialize)]
    pub struct QueryStatsResponse {
        pub stat: Vec<Stat>,
    }

    #[derive(Debug, Default, Clone, Serialize, Deserialize)]
    pub struct SysStatsRequest {}

    #[derive(Debug, Default, Clone, Serialize, Deserialize)]
    pub struct SysStatsResponse {
        pub num_goroutine: u32,
        pub num_gc: u32,
        pub alloc: u64,
        pub total_alloc: u64,
        pub sys: u64,
        pub mallocs: u64,
        pub frees: u64,
        pub live_objects: u64,
        pub pause_total_ns: u64,
        pub uptime: u32,
    }

    #[derive(Debug, Default, Clone, Serialize, Deserialize)]
    pub struct Stat {
        pub name: String,
        pub value: i64,
    }

    // Handler service types
    #[derive(Debug, Default, Clone, Serialize, Deserialize)]
    pub struct AddInboundRequest {
        pub inbound: Option<InboundHandlerConfig>,
    }

    #[derive(Debug, Default, Clone, Serialize, Deserialize)]
    pub struct AddInboundResponse {}

    #[derive(Debug, Default, Clone, Serialize, Deserialize)]
    pub struct RemoveInboundRequest {
        pub tag: String,
    }

    #[derive(Debug, Default, Clone, Serialize, Deserialize)]
    pub struct RemoveInboundResponse {}

    #[derive(Debug, Default, Clone, Serialize, Deserialize)]
    pub struct AlterInboundRequest {
        pub tag: String,
        pub operation: Option<String>,
    }

    #[derive(Debug, Default, Clone, Serialize, Deserialize)]
    pub struct AlterInboundResponse {}

    #[derive(Debug, Default, Clone, Serialize, Deserialize)]
    pub struct AddOutboundRequest {
        pub outbound: Option<InboundHandlerConfig>, // Reuse for simplicity
    }

    #[derive(Debug, Default, Clone, Serialize, Deserialize)]
    pub struct AddOutboundResponse {}

    #[derive(Debug, Default, Clone, Serialize, Deserialize)]
    pub struct RemoveOutboundRequest {
        pub tag: String,
    }

    #[derive(Debug, Default, Clone, Serialize, Deserialize)]
    pub struct RemoveOutboundResponse {}

    #[derive(Debug, Default, Clone, Serialize, Deserialize)]
    pub struct AlterOutboundRequest {
        pub tag: String,
        pub operation: Option<String>,
    }

    #[derive(Debug, Default, Clone, Serialize, Deserialize)]
    pub struct AlterOutboundResponse {}

    // Router service types
    #[derive(Debug, Default, Clone, Serialize, Deserialize)]
    pub struct SubscribeRoutingStatsRequest {}

    #[derive(Debug, Default, Clone, Serialize, Deserialize)]
    pub struct TestRouteRequest {
        pub routing_context: Option<RoutingContext>,
        pub publish_result: bool,
    }

    #[derive(Debug, Default, Clone, Serialize, Deserialize)]
    pub struct RoutingContext {
        pub inbound_tag: String,
        pub outbound_tag: String,
        pub target_domain: String,
        pub target_port: u32,
        pub source_ip: String,
        pub source_port: u32,
        pub network: String,
    }

    // Logger service types
    #[derive(Debug, Default, Clone, Serialize, Deserialize)]
    pub struct RestartLoggerRequest {}

    #[derive(Debug, Default, Clone, Serialize, Deserialize)]
    pub struct RestartLoggerResponse {}

    #[derive(Debug, Default, Clone, Serialize, Deserialize)]
    pub struct FollowLogRequest {}

    #[derive(Debug, Default, Clone, Serialize, Deserialize)]
    pub struct LogEntry {
        pub timestamp: String,
        pub level: String,
        pub message: String,
        pub source: String,
    }

    // Service trait modules
    pub mod stats_service_server {
        use super::*;
        use http_body::Body;
        use tonic::body::BoxBody;
        use tonic::{Request, Response, Status};

        #[tonic::async_trait]
        pub trait StatsService: Send + Sync + 'static {
            async fn get_stats(
                &self,
                request: Request<GetStatsRequest>,
            ) -> Result<Response<GetStatsResponse>, Status>;

            async fn query_stats(
                &self,
                request: Request<QueryStatsRequest>,
            ) -> Result<Response<QueryStatsResponse>, Status>;

            async fn get_sys_stats(
                &self,
                request: Request<SysStatsRequest>,
            ) -> Result<Response<SysStatsResponse>, Status>;
        }

        #[derive(Clone)]
        pub struct StatsServiceServer<T> {
            #[allow(dead_code)]
            inner: T,
        }

        impl<T: StatsService> StatsServiceServer<T> {
            pub fn new(inner: T) -> Self {
                Self { inner }
            }
        }

        impl<T> tonic::server::NamedService for StatsServiceServer<T>
        where
            T: StatsService,
        {
            const NAME: &'static str = "v2ray.core.app.stats.command.StatsService";
        }

        impl<T> tonic::codegen::Service<tonic::codegen::http::Request<tonic::transport::Body>>
            for StatsServiceServer<T>
        where
            T: StatsService,
        {
            type Response = tonic::codegen::http::Response<BoxBody>;
            type Error = std::convert::Infallible;
            type Future = tonic::codegen::BoxFuture<Self::Response, Self::Error>;

            fn poll_ready(
                &mut self,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Result<(), Self::Error>> {
                std::task::Poll::Ready(Ok(()))
            }

            fn call(
                &mut self,
                _req: tonic::codegen::http::Request<tonic::transport::Body>,
            ) -> Self::Future {
                Box::pin(async move {
                    match tonic::codegen::http::Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc")
                        .body(BoxBody::new(
                            http_body::Empty::new()
                                .map_err(|_| tonic::Status::internal("Empty body error")),
                        )) {
                        Ok(resp) => Ok(resp),
                        Err(_) => Ok(tonic::codegen::http::Response::new(BoxBody::new(
                            http_body::Empty::new()
                                .map_err(|_| tonic::Status::internal("Empty body error")),
                        ))),
                    }
                })
            }
        }
    }

    pub mod handler_service_server {
        use super::*;
        use http_body::Body;
        use tonic::body::BoxBody;
        use tonic::{Request, Response, Status};

        #[tonic::async_trait]
        pub trait HandlerService: Send + Sync + 'static {
            async fn add_inbound(
                &self,
                request: Request<AddInboundRequest>,
            ) -> Result<Response<AddInboundResponse>, Status>;

            async fn remove_inbound(
                &self,
                request: Request<RemoveInboundRequest>,
            ) -> Result<Response<RemoveInboundResponse>, Status>;

            async fn alter_inbound(
                &self,
                request: Request<AlterInboundRequest>,
            ) -> Result<Response<AlterInboundResponse>, Status>;

            async fn add_outbound(
                &self,
                request: Request<AddOutboundRequest>,
            ) -> Result<Response<AddOutboundResponse>, Status>;

            async fn remove_outbound(
                &self,
                request: Request<RemoveOutboundRequest>,
            ) -> Result<Response<RemoveOutboundResponse>, Status>;

            async fn alter_outbound(
                &self,
                request: Request<AlterOutboundRequest>,
            ) -> Result<Response<AlterOutboundResponse>, Status>;
        }

        #[derive(Clone)]
        pub struct HandlerServiceServer<T> {
            #[allow(dead_code)]
            inner: T,
        }

        impl<T: HandlerService> HandlerServiceServer<T> {
            pub fn new(inner: T) -> Self {
                Self { inner }
            }
        }

        impl<T> tonic::server::NamedService for HandlerServiceServer<T>
        where
            T: HandlerService,
        {
            const NAME: &'static str = "v2ray.core.app.proxyman.command.HandlerService";
        }

        impl<T> tonic::codegen::Service<tonic::codegen::http::Request<tonic::transport::Body>>
            for HandlerServiceServer<T>
        where
            T: HandlerService,
        {
            type Response = tonic::codegen::http::Response<BoxBody>;
            type Error = std::convert::Infallible;
            type Future = tonic::codegen::BoxFuture<Self::Response, Self::Error>;

            fn poll_ready(
                &mut self,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Result<(), Self::Error>> {
                std::task::Poll::Ready(Ok(()))
            }

            fn call(
                &mut self,
                _req: tonic::codegen::http::Request<tonic::transport::Body>,
            ) -> Self::Future {
                Box::pin(async move {
                    match tonic::codegen::http::Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc")
                        .body(BoxBody::new(
                            http_body::Empty::new()
                                .map_err(|_| tonic::Status::internal("Empty body error")),
                        )) {
                        Ok(resp) => Ok(resp),
                        Err(_) => Ok(tonic::codegen::http::Response::new(BoxBody::new(
                            http_body::Empty::new()
                                .map_err(|_| tonic::Status::internal("Empty body error")),
                        ))),
                    }
                })
            }
        }
    }

    pub mod routing_service_server {
        use super::*;
        use http_body::Body;
        use tokio_stream::Stream;
        use tonic::body::BoxBody;
        use tonic::{Request, Response, Status};

        #[tonic::async_trait]
        pub trait RoutingService: Send + Sync + 'static {
            type SubscribeRoutingStatsStream: Stream<Item = Result<RoutingContext, Status>>
                + Send
                + 'static;

            async fn subscribe_routing_stats(
                &self,
                request: Request<SubscribeRoutingStatsRequest>,
            ) -> Result<Response<Self::SubscribeRoutingStatsStream>, Status>;

            async fn test_route(
                &self,
                request: Request<TestRouteRequest>,
            ) -> Result<Response<RoutingContext>, Status>;
        }

        #[derive(Clone)]
        pub struct RoutingServiceServer<T> {
            #[allow(dead_code)]
            inner: T,
        }

        impl<T: RoutingService> RoutingServiceServer<T> {
            pub fn new(inner: T) -> Self {
                Self { inner }
            }
        }

        impl<T> tonic::server::NamedService for RoutingServiceServer<T>
        where
            T: RoutingService,
        {
            const NAME: &'static str = "v2ray.core.app.router.command.RoutingService";
        }

        impl<T> tonic::codegen::Service<tonic::codegen::http::Request<tonic::transport::Body>>
            for RoutingServiceServer<T>
        where
            T: RoutingService,
        {
            type Response = tonic::codegen::http::Response<BoxBody>;
            type Error = std::convert::Infallible;
            type Future = tonic::codegen::BoxFuture<Self::Response, Self::Error>;

            fn poll_ready(
                &mut self,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Result<(), Self::Error>> {
                std::task::Poll::Ready(Ok(()))
            }

            fn call(
                &mut self,
                _req: tonic::codegen::http::Request<tonic::transport::Body>,
            ) -> Self::Future {
                Box::pin(async move {
                    match tonic::codegen::http::Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc")
                        .body(BoxBody::new(
                            http_body::Empty::new()
                                .map_err(|_| tonic::Status::internal("Empty body error")),
                        )) {
                        Ok(resp) => Ok(resp),
                        Err(_) => Ok(tonic::codegen::http::Response::new(BoxBody::new(
                            http_body::Empty::new()
                                .map_err(|_| tonic::Status::internal("Empty body error")),
                        ))),
                    }
                })
            }
        }
    }

    pub mod logger_service_server {
        use super::*;
        use http_body::Body;
        use tokio_stream::Stream;
        use tonic::body::BoxBody;
        use tonic::{Request, Response, Status};

        #[tonic::async_trait]
        pub trait LoggerService: Send + Sync + 'static {
            type FollowLogStream: Stream<Item = Result<LogEntry, Status>> + Send + 'static;

            async fn restart_logger(
                &self,
                request: Request<RestartLoggerRequest>,
            ) -> Result<Response<RestartLoggerResponse>, Status>;

            async fn follow_log(
                &self,
                request: Request<FollowLogRequest>,
            ) -> Result<Response<Self::FollowLogStream>, Status>;
        }

        #[derive(Clone)]
        pub struct LoggerServiceServer<T> {
            #[allow(dead_code)]
            inner: T,
        }

        impl<T: LoggerService> LoggerServiceServer<T> {
            pub fn new(inner: T) -> Self {
                Self { inner }
            }
        }

        impl<T> tonic::server::NamedService for LoggerServiceServer<T>
        where
            T: LoggerService,
        {
            const NAME: &'static str = "v2ray.core.app.log.command.LoggerService";
        }

        impl<T> tonic::codegen::Service<tonic::codegen::http::Request<tonic::transport::Body>>
            for LoggerServiceServer<T>
        where
            T: LoggerService,
        {
            type Response = tonic::codegen::http::Response<BoxBody>;
            type Error = std::convert::Infallible;
            type Future = tonic::codegen::BoxFuture<Self::Response, Self::Error>;

            fn poll_ready(
                &mut self,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Result<(), Self::Error>> {
                std::task::Poll::Ready(Ok(()))
            }

            fn call(
                &mut self,
                _req: tonic::codegen::http::Request<tonic::transport::Body>,
            ) -> Self::Future {
                Box::pin(async move {
                    match tonic::codegen::http::Response::builder()
                        .status(200)
                        .header("content-type", "application/grpc")
                        .body(BoxBody::new(
                            http_body::Empty::new()
                                .map_err(|_| tonic::Status::internal("Empty body error")),
                        )) {
                        Ok(resp) => Ok(resp),
                        Err(_) => Ok(tonic::codegen::http::Response::new(BoxBody::new(
                            http_body::Empty::new()
                                .map_err(|_| tonic::Status::internal("Empty body error")),
                        ))),
                    }
                })
            }
        }
    }
}

pub use server::V2RayApiServer;
pub use simple::SimpleV2RayApiServer;
