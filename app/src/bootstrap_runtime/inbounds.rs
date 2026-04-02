#[cfg(feature = "router")]
use sb_core::outbound::OutboundRegistryHandle;
#[cfg(feature = "router")]
use sb_core::router::RouterHandle;
#[cfg(feature = "router")]
use std::sync::Arc;

#[cfg(feature = "router")]
pub(crate) struct InboundRuntimeDeps<'a> {
    router: &'a Arc<RouterHandle>,
    outbounds: &'a Arc<OutboundRegistryHandle>,
    #[cfg(feature = "adapters")]
    conn_tracker: Arc<sb_common::conntrack::ConnTracker>,
}

#[cfg(feature = "router")]
impl<'a> InboundRuntimeDeps<'a> {
    #[must_use]
    pub(crate) fn new(
        router: &'a Arc<RouterHandle>,
        outbounds: &'a Arc<OutboundRegistryHandle>,
        #[cfg(feature = "adapters")] conn_tracker: Arc<sb_common::conntrack::ConnTracker>,
    ) -> Self {
        Self {
            router,
            outbounds,
            #[cfg(feature = "adapters")]
            conn_tracker,
        }
    }

    #[must_use]
    pub(crate) fn start_from_ir(
        &self,
        inbounds: &[sb_config::ir::InboundIR],
    ) -> Vec<app::inbound_starter::InboundHandle> {
        app::inbound_starter::start_inbounds_from_ir(
            inbounds,
            self.router,
            self.outbounds,
            #[cfg(feature = "adapters")]
            Arc::clone(&self.conn_tracker),
        )
    }
}

#[cfg(feature = "router")]
pub(crate) fn start_inbounds_from_ir(
    inbounds: &[sb_config::ir::InboundIR],
    router: &Arc<RouterHandle>,
    outbounds: &Arc<OutboundRegistryHandle>,
    #[cfg(feature = "adapters")] conn_tracker: Arc<sb_common::conntrack::ConnTracker>,
) -> Vec<app::inbound_starter::InboundHandle> {
    InboundRuntimeDeps::new(
        router,
        outbounds,
        #[cfg(feature = "adapters")]
        conn_tracker,
    )
    .start_from_ir(inbounds)
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

    #[test]
    fn start_inbounds_facade_handles_empty_input() {
        let router = Arc::new(sb_core::router::dns_integration::setup_dns_routing());
        let handles = InboundRuntimeDeps::new(
            &router,
            &empty_outbound_handle(),
            #[cfg(feature = "adapters")]
            Arc::new(sb_common::conntrack::ConnTracker::new()),
        )
        .start_from_ir(&[]);

        assert!(handles.is_empty());
    }

    #[test]
    fn start_inbounds_facade_keeps_compat_shell() {
        let router = Arc::new(sb_core::router::dns_integration::setup_dns_routing());
        let handles = start_inbounds_from_ir(
            &[],
            &router,
            &empty_outbound_handle(),
            #[cfg(feature = "adapters")]
            Arc::new(sb_common::conntrack::ConnTracker::new()),
        );

        assert!(handles.is_empty());
    }

    #[test]
    fn wp30an_pin_inbound_starter_owner_lives_in_bootstrap_runtime() {
        let source = include_str!("inbounds.rs");
        let bootstrap = include_str!("../bootstrap.rs");

        assert!(source.contains("pub(crate) struct InboundRuntimeDeps"));
        assert!(source.contains("pub(crate) fn start_inbounds_from_ir("));
        assert!(source.contains("app::inbound_starter::start_inbounds_from_ir("));
        assert!(!bootstrap.contains("fn start_inbounds_from_ir("));
        assert!(bootstrap.contains("InboundRuntimeDeps::new("));
    }
}
