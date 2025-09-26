//! V2Ray API server implementation

use crate::{error::ApiResult, types::ApiConfig};

#[cfg(feature = "v2ray-api")]
mod grpc_impl {
    use super::*;
    use crate::v2ray::services::*;
    use std::sync::Arc;
    use tonic::transport::Server;

    /// V2Ray API server with gRPC services
    pub struct V2RayApiServer {
        config: ApiConfig,
        stats_service: Arc<StatsServiceImpl>,
        handler_service: Arc<HandlerServiceImpl>,
        router_service: Arc<RouterServiceImpl>,
        logger_service: Arc<LoggerServiceImpl>,
    }

    impl V2RayApiServer {
        /// Create a new V2Ray API server
        pub fn new(config: ApiConfig) -> ApiResult<Self> {
            let stats_service = Arc::new(StatsServiceImpl::new());
            let handler_service = Arc::new(HandlerServiceImpl::new());
            let router_service = Arc::new(RouterServiceImpl::new());
            let logger_service = Arc::new(LoggerServiceImpl::new());

            Ok(Self {
                config,
                stats_service,
                handler_service,
                router_service,
                logger_service,
            })
        }

        /// Start the V2Ray API gRPC server
        pub async fn start(&self) -> ApiResult<()> {
            log::info!(
                "Starting V2Ray API gRPC server on {}",
                self.config.listen_addr
            );

            let stats_service = self.stats_service.clone();
            let handler_service = self.handler_service.clone();
            let router_service = self.router_service.clone();
            let logger_service = self.logger_service.clone();

            Server::builder()
                .add_service(StatsServiceServer::new(stats_service))
                .add_service(HandlerServiceServer::new(handler_service))
                .add_service(RoutingServiceServer::new(router_service))
                .add_service(LoggerServiceServer::new(logger_service))
                .serve(self.config.listen_addr)
                .await
                .map_err(|e| crate::error::ApiError::Internal { source: e.into() })?;

            Ok(())
        }
    }
}

#[cfg(not(feature = "v2ray-api"))]
mod simple_impl {
    use super::*;
    use crate::v2ray::simple::SimpleV2RayApiServer;

    /// V2Ray API server using simplified implementation
    pub struct V2RayApiServer {
        inner: SimpleV2RayApiServer,
    }

    impl V2RayApiServer {
        /// Create a new V2Ray API server
        pub fn new(config: ApiConfig) -> ApiResult<Self> {
            let inner = SimpleV2RayApiServer::new(config)?;
            Ok(Self { inner })
        }

        /// Start the V2Ray API server (simplified implementation)
        pub async fn start(&self) -> ApiResult<()> {
            log::info!("Starting V2Ray API server (simplified implementation)");
            self.inner.start().await
        }

        /// Get the inner simple server for additional operations
        pub fn inner(&self) -> &SimpleV2RayApiServer {
            &self.inner
        }
    }
}

#[cfg(feature = "v2ray-api")]
pub use grpc_impl::V2RayApiServer;

#[cfg(not(feature = "v2ray-api"))]
pub use simple_impl::V2RayApiServer;
