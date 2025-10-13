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
                crate::ir::InboundType::Direct => "direct",
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
            let ty = match outbound.ty {
                crate::ir::OutboundType::Direct => "direct",
                crate::ir::OutboundType::Http => "http",
                crate::ir::OutboundType::Socks => "socks",
                crate::ir::OutboundType::Block => "block",
                crate::ir::OutboundType::Selector => "selector",
                crate::ir::OutboundType::Shadowtls => "shadowtls",
                crate::ir::OutboundType::Hysteria2 => "hysteria2",
                crate::ir::OutboundType::Vless => "vless",
                crate::ir::OutboundType::Vmess => "vmess",
                crate::ir::OutboundType::Trojan => "trojan",
                crate::ir::OutboundType::Ssh => "ssh",
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

    Value::Object(root)
}
