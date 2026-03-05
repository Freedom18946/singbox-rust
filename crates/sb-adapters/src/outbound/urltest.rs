use std::sync::Arc;
use std::time::Duration;

use sb_config::ir::OutboundIR;
use sb_core::adapter::{registry, OutboundConnector, OutboundParam, UdpOutboundFactory};
use sb_core::outbound::selector_group::UrlTestOptions;
use sb_core::outbound::selector_group::{ProxyMember, SelectorGroup};

type OutboundBuilderResult = Option<(
    Arc<dyn OutboundConnector>,
    Option<Arc<dyn UdpOutboundFactory>>,
)>;

pub fn build_urltest_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    let name = ir
        .name
        .clone()
        .or(param.name.clone())
        .unwrap_or_else(|| "urltest".to_string());
    let member_tags = ir.members.clone().unwrap_or_default();

    let mut members = Vec::new();
    for tag in member_tags {
        if let Some(connector) = ctx.bridge.get_member(&tag) {
            let udp_factory = ctx.bridge.find_udp_factory(&tag);
            members.push(ProxyMember::new(tag, connector, udp_factory));
        } else {
            tracing::warn!("UrlTest {} member {} not found", name, tag);
        }
    }

    let test_url = ir
        .test_url
        .clone()
        .unwrap_or_else(|| "http://cp.cloudflare.com".to_string());
    let interval = Duration::from_millis(ir.test_interval_ms.unwrap_or(600000));
    let timeout = Duration::from_millis(ir.test_timeout_ms.unwrap_or(5000));
    let tolerance = ir.test_tolerance_ms.unwrap_or(50);

    let cache_file = ctx.context.cache_file.clone();
    let urltest_history = ctx.context.urltest_history.clone();
    let group = Arc::new(SelectorGroup::new_urltest(
        name,
        members,
        UrlTestOptions {
            test_url,
            interval,
            timeout,
            tolerance_ms: tolerance,
            cache_file,
            urltest_history,
        },
    ));

    Some((group.clone(), Some(group)))
}
