use std::sync::Arc;

use sb_config::ir::OutboundIR;
use sb_core::adapter::{registry, OutboundConnector, OutboundParam, UdpOutboundFactory};
use sb_core::outbound::selector_group::{ProxyMember, SelectorGroup};

type OutboundBuilderResult = Option<(
    Arc<dyn OutboundConnector>,
    Option<Arc<dyn UdpOutboundFactory>>,
)>;

pub fn build_selector_outbound(
    param: &OutboundParam,
    ir: &OutboundIR,
    ctx: &registry::AdapterOutboundContext,
) -> OutboundBuilderResult {
    let name = ir
        .name
        .clone()
        .or(param.name.clone())
        .unwrap_or_else(|| "selector".to_string());
    let member_tags = ir.members.clone().unwrap_or_default();

    let mut members = Vec::new();
    for tag in member_tags {
        if let Some(connector) = ctx.bridge.get_member(&tag) {
            let udp_factory = ctx.bridge.find_udp_factory(&tag);
            members.push(ProxyMember::new(tag, connector, udp_factory));
        } else {
            tracing::warn!("Selector {} member {} not found", name, tag);
        }
    }

    let default = ir.default_member.clone();
    let cache_file = ctx.context.cache_file.clone();
    let urltest_history = ctx.context.urltest_history.clone();
    let group = Arc::new(SelectorGroup::new_manual(
        name,
        members,
        default,
        cache_file,
        urltest_history,
    ));

    Some((group.clone(), Some(group)))
}
