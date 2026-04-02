use anyhow::{anyhow, Result};
use sb_core::outbound::OutboundRegistryHandle;
use std::sync::Arc;
use tokio::time::Duration;

#[cfg(any(feature = "clash_api", feature = "v2ray_api"))]
use crate::bootstrap_runtime::api_services::ServiceHandle;

pub struct Runtime {
    pub router: Arc<sb_core::router::engine::RouterHandle>,
    pub outbounds: Arc<OutboundRegistryHandle>,
    pub inbounds: Vec<app::inbound_starter::InboundHandle>,
    #[cfg(any(feature = "clash_api", feature = "v2ray_api"))]
    pub(crate) services: Vec<ServiceHandle>,
}

impl Runtime {
    #[must_use]
    pub fn new(
        router: Arc<sb_core::router::engine::RouterHandle>,
        outbounds: Arc<OutboundRegistryHandle>,
        inbounds: Vec<app::inbound_starter::InboundHandle>,
        #[cfg(any(feature = "clash_api", feature = "v2ray_api"))] services: Vec<ServiceHandle>,
    ) -> Self {
        Self {
            router,
            outbounds,
            inbounds,
            #[cfg(any(feature = "clash_api", feature = "v2ray_api"))]
            services,
        }
    }

    pub async fn shutdown(self, timeout: Duration) -> Result<()> {
        let Self {
            inbounds,
            #[cfg(any(feature = "clash_api", feature = "v2ray_api"))]
            services,
            ..
        } = self;

        let shutdown = async {
            #[cfg(any(feature = "clash_api", feature = "v2ray_api"))]
            {
                for service in services {
                    service.shutdown().await;
                }
            }
            for inbound in inbounds {
                inbound.shutdown().await;
            }
        };

        tokio::time::timeout(timeout, shutdown)
            .await
            .map_err(|_| anyhow!("shutdown timeout after {timeout:?}"))?;
        Ok(())
    }
}

#[cfg(all(test, feature = "router"))]
mod tests {
    use super::*;
    use sb_core::outbound::{OutboundImpl, OutboundRegistry};
    use std::collections::HashMap;

    fn empty_outbound_handle() -> Arc<OutboundRegistryHandle> {
        let registry = OutboundRegistry::new(HashMap::<String, OutboundImpl>::new());
        Arc::new(OutboundRegistryHandle::new(registry))
    }

    #[tokio::test]
    async fn runtime_shutdown_succeeds_with_no_children() -> anyhow::Result<()> {
        let runtime = Runtime::new(
            Arc::new(sb_core::router::dns_integration::setup_dns_routing()),
            empty_outbound_handle(),
            Vec::new(),
            #[cfg(any(feature = "clash_api", feature = "v2ray_api"))]
            Vec::new(),
        );

        runtime.shutdown(Duration::from_millis(10)).await
    }

    #[cfg(any(feature = "clash_api", feature = "v2ray_api"))]
    #[tokio::test]
    async fn runtime_shutdown_times_out_when_service_never_finishes() {
        let (shutdown_tx, _shutdown_rx) = tokio::sync::oneshot::channel();
        let join = tokio::spawn(async {
            tokio::time::sleep(Duration::from_millis(100)).await;
        });
        let runtime = Runtime::new(
            Arc::new(sb_core::router::dns_integration::setup_dns_routing()),
            empty_outbound_handle(),
            Vec::new(),
            vec![ServiceHandle {
                name: "hung",
                shutdown: shutdown_tx,
                join,
            }],
        );

        let error = runtime
            .shutdown(Duration::from_millis(10))
            .await
            .expect_err("service should keep runtime shutdown waiting past timeout");

        assert!(error.to_string().contains("shutdown timeout"));
    }

    #[test]
    fn wp30an_pin_runtime_shell_owner_lives_in_bootstrap_runtime() {
        let source = include_str!("runtime_shell.rs");
        let bootstrap = include_str!("../bootstrap.rs");

        assert!(source.contains("pub struct Runtime"));
        assert!(source.contains("pub fn new("));
        assert!(!bootstrap.contains("pub struct Runtime {"));
        assert!(bootstrap.contains("Runtime::new("));
        assert!(bootstrap.contains("pub use crate::bootstrap_runtime::runtime_shell::Runtime;"));
    }
}
