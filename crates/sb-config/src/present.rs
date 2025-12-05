//! Configuration presentation layer: conversion and formatting utilities.

use crate::ir::ConfigIR;
use crate::Config;
use anyhow::Result;
use serde_json::{Map, Value};

/// Convert Config to ConfigIR for routing engine
pub fn to_ir(cfg: &Config) -> Result<ConfigIR> {
    Ok(cfg.ir().clone())
}

/// Convert ConfigIR back to JSON view (legacy helper)
pub fn to_view(ir: &ConfigIR) -> Value {
    let mut root = Map::new();
    root.insert("schema_version".into(), Value::from(2));

    let inbounds = ir
        .inbounds
        .iter()
        .map(|inbound| {
            let mut obj = Map::new();
            let listen = format!("{}:{}", inbound.listen, inbound.port);
            obj.insert("listen".into(), Value::from(listen));
            let ty = match inbound.ty {
                crate::ir::InboundType::Http => "http",
                crate::ir::InboundType::Socks => "socks",
                crate::ir::InboundType::Tun => "tun",
                crate::ir::InboundType::Mixed => "mixed",
                crate::ir::InboundType::Redirect => "redirect",
                crate::ir::InboundType::Tproxy => "tproxy",
                crate::ir::InboundType::Direct => "direct",
                crate::ir::InboundType::Shadowsocks => "shadowsocks",
                crate::ir::InboundType::Vmess => "vmess",
                crate::ir::InboundType::Vless => "vless",
                crate::ir::InboundType::Trojan => "trojan",
                crate::ir::InboundType::Naive => "naive",
                crate::ir::InboundType::Shadowtls => "shadowtls",
                crate::ir::InboundType::Anytls => "anytls",
                crate::ir::InboundType::Hysteria => "hysteria",
                crate::ir::InboundType::Hysteria2 => "hysteria2",
                crate::ir::InboundType::Tuic => "tuic",
                crate::ir::InboundType::Dns => "dns",
                crate::ir::InboundType::Ssh => "ssh",
            };
            obj.insert("type".into(), Value::from(ty));
            Value::Object(obj)
        })
        .collect();
    root.insert("inbounds".into(), Value::Array(inbounds));

    let outbounds = ir
        .outbounds
        .iter()
        .map(|outbound| {
            let mut obj = Map::new();
            if let Some(name) = &outbound.name {
                obj.insert("name".into(), Value::from(name.clone()));
            }
            if let Some(server) = &outbound.server {
                obj.insert("server".into(), Value::from(server.clone()));
            }
            if let Some(port) = outbound.port {
                obj.insert("port".into(), Value::from(port));
            }
            if let Some(uuid) = &outbound.uuid {
                obj.insert("uuid".into(), Value::from(uuid.clone()));
            }
            if let Some(password) = &outbound.password {
                obj.insert("password".into(), Value::from(password.clone()));
            }
            if let Some(token) = &outbound.token {
                obj.insert("token".into(), Value::from(token.clone()));
            }
            if let Some(cc) = &outbound.congestion_control {
                obj.insert("congestion_control".into(), Value::from(cc.clone()));
            }
            if let Some(alpn) = &outbound.alpn {
                obj.insert("alpn".into(), Value::from(alpn.clone()));
            }
            if let Some(skip) = outbound.skip_cert_verify {
                obj.insert("skip_cert_verify".into(), Value::from(skip));
            }
            if let Some(mode) = &outbound.udp_relay_mode {
                obj.insert("udp_relay_mode".into(), Value::from(mode.clone()));
            }
            if let Some(udp_stream) = outbound.udp_over_stream {
                obj.insert("udp_over_stream".into(), Value::from(udp_stream));
            }
            if let Some(service) = &outbound.grpc_service {
                obj.insert("grpc_service".into(), Value::from(service.clone()));
            }
            if let Some(method) = &outbound.grpc_method {
                obj.insert("grpc_method".into(), Value::from(method.clone()));
            }
            if let Some(authority) = &outbound.grpc_authority {
                obj.insert("grpc_authority".into(), Value::from(authority.clone()));
            }
            if !outbound.grpc_metadata.is_empty() {
                obj.insert(
                    "grpc_metadata".into(),
                    Value::Array(
                        outbound
                            .grpc_metadata
                            .iter()
                            .map(|h| {
                                let mut map = Map::new();
                                map.insert("name".into(), Value::from(h.key.clone()));
                                map.insert("value".into(), Value::from(h.value.clone()));
                                Value::Object(map)
                            })
                            .collect(),
                    ),
                );
            }
            if let Some(path) = &outbound.http_upgrade_path {
                obj.insert("http_upgrade_path".into(), Value::from(path.clone()));
            }
            if !outbound.http_upgrade_headers.is_empty() {
                obj.insert(
                    "http_upgrade_headers".into(),
                    Value::Array(
                        outbound
                            .http_upgrade_headers
                            .iter()
                            .map(|h| {
                                let mut map = Map::new();
                                map.insert("name".into(), Value::from(h.key.clone()));
                                map.insert("value".into(), Value::from(h.value.clone()));
                                Value::Object(map)
                            })
                            .collect(),
                    ),
                );
            }
            if let Some(up) = outbound.up_mbps {
                obj.insert("up_mbps".into(), Value::from(up));
            }
            if let Some(down) = outbound.down_mbps {
                obj.insert("down_mbps".into(), Value::from(down));
            }
            if let Some(obfs) = &outbound.obfs {
                obj.insert("obfs".into(), Value::from(obfs.clone()));
            }
            if let Some(salamander) = &outbound.salamander {
                obj.insert("salamander".into(), Value::from(salamander.clone()));
            }
            if outbound.brutal_up_mbps.is_some() || outbound.brutal_down_mbps.is_some() {
                let mut brutal = Map::new();
                if let Some(up) = outbound.brutal_up_mbps {
                    brutal.insert("up_mbps".into(), Value::from(up));
                }
                if let Some(down) = outbound.brutal_down_mbps {
                    brutal.insert("down_mbps".into(), Value::from(down));
                }
                obj.insert("brutal".into(), Value::Object(brutal));
            }
            if let Some(credentials) = &outbound.credentials {
                let mut cred = Map::new();
                if let Some(u) = &credentials.username {
                    cred.insert("username".into(), Value::from(u.clone()));
                }
                if let Some(p) = &credentials.password {
                    cred.insert("password".into(), Value::from(p.clone()));
                }
                obj.insert("credentials".into(), Value::Object(cred));
            }
            if let Some(members) = &outbound.members {
                obj.insert("outbounds".into(), Value::from(members.clone()));
            }
            if let Some(default_member) = &outbound.default_member {
                obj.insert("default".into(), Value::from(default_member.clone()));
            }
            if let Some(method) = &outbound.method {
                obj.insert("method".into(), Value::from(method.clone()));
            }
            if let Some(transport) = &outbound.transport {
                obj.insert(
                    "transport".into(),
                    Value::Array(transport.iter().map(|s| Value::from(s.clone())).collect()),
                );
            }
            if let Some(url) = &outbound.test_url {
                obj.insert("url".into(), Value::from(url.clone()));
            }
            if let Some(interval_ms) = outbound.test_interval_ms {
                obj.insert("interval_ms".into(), Value::from(interval_ms));
            }
            if let Some(timeout_ms) = outbound.test_timeout_ms {
                obj.insert("timeout_ms".into(), Value::from(timeout_ms));
            }
            if let Some(tolerance_ms) = outbound.test_tolerance_ms {
                obj.insert("tolerance_ms".into(), Value::from(tolerance_ms));
            }
            if let Some(interrupt) = outbound.interrupt_exist_connections {
                obj.insert("interrupt_exist_connections".into(), Value::from(interrupt));
            }
            let ty = match outbound.ty {
                crate::ir::OutboundType::Direct => "direct",
                crate::ir::OutboundType::Http => "http",
                crate::ir::OutboundType::Socks => "socks",
                crate::ir::OutboundType::Block => "block",
                crate::ir::OutboundType::Selector => "selector",
                crate::ir::OutboundType::Shadowsocks => "shadowsocks",
                crate::ir::OutboundType::UrlTest => "urltest",
                crate::ir::OutboundType::Shadowtls => "shadowtls",
                crate::ir::OutboundType::Hysteria2 => "hysteria2",
                crate::ir::OutboundType::Tuic => "tuic",
                crate::ir::OutboundType::Vless => "vless",
                crate::ir::OutboundType::Vmess => "vmess",
                crate::ir::OutboundType::Trojan => "trojan",
                crate::ir::OutboundType::Ssh => "ssh",
                crate::ir::OutboundType::Dns => "dns",
                crate::ir::OutboundType::Tor => "tor",
                crate::ir::OutboundType::Anytls => "anytls",
                crate::ir::OutboundType::Hysteria => "hysteria",
                crate::ir::OutboundType::Wireguard => "wireguard",
                crate::ir::OutboundType::Tailscale => "tailscale",
                crate::ir::OutboundType::ShadowsocksR => "shadowsocksr",
            };
            obj.insert("type".into(), Value::from(ty));
            Value::Object(obj)
        })
        .collect();
    root.insert("outbounds".into(), Value::Array(outbounds));

    let mut rules = Vec::new();
    for rule in &ir.route.rules {
        let mut obj = Map::new();
        if !rule.domain.is_empty() {
            obj.insert("domain".into(), Value::from(rule.domain.clone()));
        }
        if !rule.geoip.is_empty() {
            obj.insert("geoip".into(), Value::from(rule.geoip.clone()));
        }
        if !rule.port.is_empty() {
            obj.insert("port".into(), Value::from(rule.port.clone()));
        }
        if !rule.network.is_empty() {
            obj.insert("network".into(), Value::from(rule.network.clone()));
        }
        if let Some(outbound) = &rule.outbound {
            obj.insert("outbound".into(), Value::from(outbound.clone()));
        }
        rules.push(Value::Object(obj));
    }
    let mut route = Map::new();
    route.insert("rules".into(), Value::Array(rules));
    if let Some(default) = &ir.route.default {
        route.insert("default".into(), Value::from(default.clone()));
    }
    root.insert("route".into(), Value::Object(route));

    // Optional: NTP view (compat with Go 1.12.x)
    if let Some(ntp) = &ir.ntp {
        use std::time::Duration;
        let mut ntp_obj = Map::new();
        if let Some(server) = &ntp.server {
            ntp_obj.insert("server".into(), Value::from(server.clone()));
        }
        if let Some(port) = ntp.server_port {
            ntp_obj.insert("server_port".into(), Value::from(port));
        }
        // Render interval as human-ish string like "30m0s" if provided
        if let Some(ms) = ntp.interval_ms {
            let secs = Duration::from_millis(ms).as_secs();
            // Format as XmYs (simple formatting to match examples like 30m0s)
            let minutes = secs / 60;
            let seconds = secs % 60;
            let text = format!("{}m{}s", minutes, seconds);
            ntp_obj.insert("interval".into(), Value::from(text));
        }
        if !ntp_obj.is_empty() {
            root.insert("ntp".into(), Value::Object(ntp_obj));
        }
    }

    Value::Object(root)
}
