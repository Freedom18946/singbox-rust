mod quic;
mod shadowsocks;
mod simple;
mod v2ray;

use sb_config::ir::{ConfigIR, HeaderEntry, OutboundIR, OutboundType};
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs};

pub(crate) use quic::{BrutalSpec, Hysteria2Spec, TuicSpec, UdpRelayModeSpec};
pub(crate) use shadowsocks::{ShadowsocksCipherSpec, ShadowsocksSpec};
pub(crate) use simple::{HttpProxySpec, SocksProxySpec};
pub(crate) use v2ray::{TrojanSpec, VlessSpec, VmessSpec};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FirstPassConcreteOutbound {
    Direct,
    Block,
    Socks(SocksProxySpec),
    Http(HttpProxySpec),
    Hysteria2(Hysteria2Spec),
    Tuic(TuicSpec),
    Shadowsocks(ShadowsocksSpec),
    Vless(VlessSpec),
    Vmess(VmessSpec),
    Trojan(TrojanSpec),
}

pub(crate) fn build_first_pass_concrete_outbounds(
    ir: &ConfigIR,
) -> HashMap<String, FirstPassConcreteOutbound> {
    let mut map = HashMap::new();

    for outbound in &ir.outbounds {
        let Some(name) = outbound_name(outbound) else {
            continue;
        };

        if let Some(spec) = build_first_pass_concrete_outbound(&name, outbound) {
            map.insert(name, spec);
        }
    }

    map
}

pub(crate) fn ensure_default_outbound_aliases(
    map: &mut HashMap<String, FirstPassConcreteOutbound>,
) {
    map.entry("direct".to_string())
        .or_insert(FirstPassConcreteOutbound::Direct);
    map.entry("block".to_string())
        .or_insert(FirstPassConcreteOutbound::Block);
}

fn build_first_pass_concrete_outbound(
    outbound_name: &str,
    outbound: &OutboundIR,
) -> Option<FirstPassConcreteOutbound> {
    match outbound.ty {
        OutboundType::Direct => Some(FirstPassConcreteOutbound::Direct),
        OutboundType::Block => Some(FirstPassConcreteOutbound::Block),
        OutboundType::Socks | OutboundType::Http => {
            simple::build_simple_outbound(outbound).map(Into::into)
        }
        OutboundType::Hysteria2 | OutboundType::Tuic => {
            quic::build_quic_outbound(outbound_name, outbound).map(Into::into)
        }
        OutboundType::Shadowsocks => {
            shadowsocks::build_shadowsocks_outbound(outbound_name, outbound).map(Into::into)
        }
        OutboundType::Vless | OutboundType::Vmess | OutboundType::Trojan => {
            v2ray::build_v2ray_outbound(outbound_name, outbound).map(Into::into)
        }
        _ => None,
    }
}

pub(crate) fn shared_alpn_tokens(outbound: &OutboundIR) -> Option<Vec<String>> {
    outbound
        .tls_alpn
        .clone()
        .or_else(|| outbound.alpn.as_ref().map(|raw| parse_alpn_tokens(raw)))
}

pub(crate) fn map_header_entries(entries: &[HeaderEntry]) -> Vec<(String, String)> {
    entries
        .iter()
        .map(|entry| (entry.key.clone(), entry.value.clone()))
        .collect()
}

pub(crate) fn resolve_host_port(host: &str, port: u16) -> Option<SocketAddr> {
    let query = format!("{host}:{port}");
    query.to_socket_addrs().ok()?.next()
}

fn outbound_name(outbound: &OutboundIR) -> Option<String> {
    match &outbound.name {
        Some(name) if !name.is_empty() => Some(name.clone()),
        _ => None,
    }
}

fn parse_alpn_tokens(src: &str) -> Vec<String> {
    src.split(',')
        .flat_map(|part| part.split_whitespace())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_config::ir::OutboundIR;

    #[test]
    fn first_pass_builder_collects_supported_families_and_keeps_default_aliases_separate() {
        let mut ir = ConfigIR::default();
        ir.outbounds.push(OutboundIR {
            ty: OutboundType::Direct,
            name: Some("direct-a".to_string()),
            ..Default::default()
        });
        ir.outbounds.push(OutboundIR {
            ty: OutboundType::Block,
            name: Some("block-a".to_string()),
            ..Default::default()
        });
        ir.outbounds.push(OutboundIR {
            ty: OutboundType::Socks,
            name: Some("socks-a".to_string()),
            server: Some("127.0.0.1".to_string()),
            port: Some(1080),
            ..Default::default()
        });
        ir.outbounds.push(OutboundIR {
            ty: OutboundType::Http,
            name: Some("http-a".to_string()),
            server: Some("127.0.0.1".to_string()),
            port: Some(8080),
            ..Default::default()
        });
        ir.outbounds.push(OutboundIR {
            ty: OutboundType::Selector,
            name: Some("selector-a".to_string()),
            members: Some(vec!["direct-a".to_string()]),
            ..Default::default()
        });

        let mut map = build_first_pass_concrete_outbounds(&ir);
        assert_eq!(map.len(), 4);
        assert!(matches!(
            map.get("direct-a"),
            Some(FirstPassConcreteOutbound::Direct)
        ));
        assert!(matches!(
            map.get("block-a"),
            Some(FirstPassConcreteOutbound::Block)
        ));
        assert!(matches!(
            map.get("socks-a"),
            Some(FirstPassConcreteOutbound::Socks(_))
        ));
        assert!(matches!(
            map.get("http-a"),
            Some(FirstPassConcreteOutbound::Http(_))
        ));
        assert!(!map.contains_key("selector-a"));

        ensure_default_outbound_aliases(&mut map);
        assert!(matches!(
            map.get("direct"),
            Some(FirstPassConcreteOutbound::Direct)
        ));
        assert!(matches!(
            map.get("block"),
            Some(FirstPassConcreteOutbound::Block)
        ));
    }

    #[test]
    fn shared_alpn_tokens_prefers_tls_list_and_splits_legacy_string() {
        let outbound = OutboundIR {
            ty: OutboundType::Trojan,
            name: Some("trojan".to_string()),
            tls_alpn: Some(vec!["h2".to_string(), "http/1.1".to_string()]),
            alpn: Some("ignored".to_string()),
            ..Default::default()
        };
        assert_eq!(
            shared_alpn_tokens(&outbound),
            Some(vec!["h2".to_string(), "http/1.1".to_string()])
        );

        let outbound = OutboundIR {
            ty: OutboundType::Trojan,
            name: Some("trojan".to_string()),
            alpn: Some("h3, hq-29".to_string()),
            ..Default::default()
        };
        assert_eq!(
            shared_alpn_tokens(&outbound),
            Some(vec!["h3".to_string(), "hq-29".to_string()])
        );
    }

    #[test]
    fn wp30am_pin_first_pass_owner_lives_in_outbound_builder_tree() {
        let bootstrap = include_str!("../bootstrap.rs");
        let source = include_str!("mod.rs");

        assert!(source.contains("pub(crate) fn build_first_pass_concrete_outbounds"));
        assert!(source.contains("mod simple;"));
        assert!(source.contains("mod quic;"));
        assert!(source.contains("mod shadowsocks;"));
        assert!(source.contains("mod v2ray;"));
        assert!(!bootstrap.contains("fn resolve_host_port("));
        assert!(!bootstrap.contains("fn parse_alpn_tokens("));
        assert!(!bootstrap.contains("fn map_header_entries("));
    }

    #[test]
    fn wp30am_pin_bootstrap_delegates_first_pass_owner() {
        let bootstrap = include_str!("../bootstrap.rs");

        assert!(
            bootstrap.contains("crate::outbound_builder::build_first_pass_concrete_outbounds(ir)")
        );
        assert!(bootstrap
            .contains("crate::outbound_builder::ensure_default_outbound_aliases(&mut map);"));
        assert!(bootstrap.contains("crate::outbound_groups::bind_selector_outbound_groups("));
        assert!(!bootstrap.contains("OutboundType::Hysteria2 =>"));
        assert!(!bootstrap.contains("OutboundType::Shadowsocks =>"));
        assert!(!bootstrap.contains("OutboundType::Vless =>"));
    }
}
