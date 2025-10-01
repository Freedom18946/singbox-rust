//! Configuration presentation layer: conversion and formatting.
//!
//! This module provides two primary functions:
//!
//! 1. **Conversion (`to_ir`)**: The canonical transformation from user-facing `Config`
//!    to the intermediate representation (`ConfigIR`) consumed by the routing engine
//!    and runtime adapters. This is the **single source of truth** for Config→IR
//!    conversion, invoked by `Config::build_registry_and_router` for validation and
//!    by runtime components for actual IR consumption.
//!
//! 2. **Formatting (`to_view`)**: Transforms `ConfigIR` into external JSON formats
//!    for compatibility with other tools (e.g., `FormatProfile::Go1124` for sing-box
//!    Go version compatibility). Used for config inspection, debugging, and
//!    interoperability.
//!
//! ## Design rationale
//!
//! - **Why not merge with `ir.rs`?** The `ir` module defines data structures;
//!   this module handles transformations. Separation keeps concerns distinct.
//! - **Why "present"?** The name reflects "presentation layer" - bridging
//!   user-facing config and internal IR, plus external view formatting.

use crate::ir::{ConfigIR, InboundIR, InboundType, OutboundIR, OutboundType, RuleIR};

use crate::{Config, Inbound, Outbound};
use anyhow::Result;
use serde_json::{Map, Value};

/// Convert Config to ConfigIR for routing engine
pub fn to_ir(cfg: &Config) -> Result<ConfigIR> {
    let mut ir = ConfigIR::default();

    // Convert inbounds
    for inbound in &cfg.inbounds {
        let (ty, listen_addr, port) = match inbound {
            Inbound::Http { listen } => {
                let (addr, port) = parse_listen_addr(listen)?;
                (InboundType::Http, addr, port)
            }
            Inbound::Socks { listen } => {
                let (addr, port) = parse_listen_addr(listen)?;
                (InboundType::Socks, addr, port)
            }
        };
        ir.inbounds.push(InboundIR {
            ty,
            listen: listen_addr,
            port,
            sniff: false,
            udp: false,
            basic_auth: None,
        });
    }

    // Convert outbounds
    for outbound in &cfg.outbounds {
        let outbound_ir = match outbound {
            Outbound::Direct { name } => OutboundIR {
                ty: OutboundType::Direct,
                name: Some(name.clone()),
                ..Default::default()
            },
            Outbound::Block { name } => OutboundIR {
                ty: OutboundType::Block,
                name: Some(name.clone()),
                ..Default::default()
            },
            Outbound::Socks5 {
                name,
                server,
                port,
                auth,
            } => OutboundIR {
                ty: OutboundType::Socks,
                name: Some(name.clone()),
                server: Some(server.clone()),
                port: Some(*port),
                credentials: auth.as_ref().map(|a| crate::ir::Credentials {
                    username: Some(a.username.clone()),
                    password: Some(a.password.clone()),
                    username_env: None,
                    password_env: None,
                }),
                ..Default::default()
            },
            Outbound::Http {
                name,
                server,
                port,
                auth,
            } => OutboundIR {
                ty: OutboundType::Http,
                name: Some(name.clone()),
                server: Some(server.clone()),
                port: Some(*port),
                credentials: auth.as_ref().map(|a| crate::ir::Credentials {
                    username: Some(a.username.clone()),
                    password: Some(a.password.clone()),
                    username_env: None,
                    password_env: None,
                }),
                ..Default::default()
            },
            Outbound::Vless {
                name,
                server,
                port,
                uuid,
                flow,
                network,
                packet_encoding,
                connect_timeout_sec: _,
            } => OutboundIR {
                ty: OutboundType::Vless,
                name: Some(name.clone()),
                server: Some(server.clone()),
                port: Some(*port),
                uuid: Some(uuid.clone()),
                flow: flow.clone(),
                network: Some(network.clone()),
                packet_encoding: packet_encoding.clone(),
                ..Default::default()
            }
        };
        ir.outbounds.push(outbound_ir);
    }

    // Convert rules
    for rule in &cfg.rules {
        let rule_ir = RuleIR {
            domain: rule.domain_suffix.clone(),
            outbound: Some(rule.outbound.clone()),
            ..Default::default()
        };
        ir.route.rules.push(rule_ir);
    }

    // Set default outbound
    ir.route.default = cfg.default_outbound.clone();

    Ok(ir)
}

fn parse_listen_addr(listen: &str) -> Result<(String, u16)> {
    if let Some((host, port_str)) = listen.rsplit_once(':') {
        let port = port_str
            .parse::<u16>()
            .map_err(|e| anyhow::anyhow!("invalid port in listen address '{}': {}", listen, e))?;
        Ok((host.to_string(), port))
    } else {
        Err(anyhow::anyhow!("invalid listen address format: {}", listen))
    }
}

pub enum FormatProfile {
    Go1124, /*, Rich*/
}

pub fn to_view(cfg: &ConfigIR, prof: FormatProfile) -> Value {
    match prof {
        FormatProfile::Go1124 => go_1124_view(cfg),
        // FormatProfile::Rich => rich_view(cfg),
    }
}

fn go_1124_view(cfg: &ConfigIR) -> Value {
    // Convert ConfigIR to JSON view for compatibility
    let mut root = Map::new();

    // Convert inbounds
    let inbounds: Vec<Value> = cfg
        .inbounds
        .iter()
        .map(|ib| {
            let mut m = Map::new();
            m.insert("type".into(), Value::String(ib.ty_str().to_string()));
            m.insert(
                "listen".into(),
                Value::String(format!("{}:{}", ib.listen, ib.port)),
            );
            if ib.sniff {
                m.insert("sniff".into(), Value::Bool(true));
            }
            if ib.udp {
                m.insert("udp".into(), Value::Bool(true));
            }
            Value::Object(m)
        })
        .collect();

    // Convert outbounds
    let outbounds: Vec<Value> = cfg
        .outbounds
        .iter()
        .map(|ob| {
            let mut m = Map::new();
            m.insert("type".into(), Value::String(ob.ty_str().to_string()));
            if let Some(name) = &ob.name {
                m.insert("tag".into(), Value::String(name.clone()));
            }
            if let Some(server) = &ob.server {
                m.insert("server".into(), Value::String(server.clone()));
            }
            if let Some(port) = ob.port {
                m.insert("server_port".into(), Value::Number(port.into()));
            }
            Value::Object(m)
        })
        .collect();

    // Convert routing rules
    let rules: Vec<Value> = cfg
        .route
        .rules
        .iter()
        .map(|rule| {
            let mut m = Map::new();
            if !rule.domain.is_empty() {
                if rule.domain.len() == 1 {
                    m.insert(
                        "domain_suffix".into(),
                        Value::String(rule.domain[0].clone()),
                    );
                } else {
                    m.insert(
                        "domain_suffix".into(),
                        Value::Array(
                            rule.domain
                                .iter()
                                .map(|d| Value::String(d.clone()))
                                .collect(),
                        ),
                    );
                }
            }
            if let Some(outbound) = &rule.outbound {
                m.insert("outbound".into(), Value::String(outbound.clone()));
            }
            Value::Object(m)
        })
        .collect();

    let mut route = Map::new();
    route.insert("rules".into(), Value::Array(rules));
    if let Some(default) = &cfg.route.default {
        route.insert("final".into(), Value::String(default.clone()));
    }

    if !inbounds.is_empty() {
        root.insert("inbounds".into(), Value::Array(inbounds));
    }
    if !outbounds.is_empty() {
        root.insert("outbounds".into(), Value::Array(outbounds));
    }
    if !route.is_empty() {
        root.insert("route".into(), Value::Object(route));
    }

    Value::Object(root)
}

impl InboundIR {
    fn ty_str(&self) -> &'static str {
        match self.ty {
            InboundType::Http => "http",
            InboundType::Socks => "socks",
            InboundType::Tun => "tun",
        }
    }
}

#[cfg(any(test, feature = "dev-cli"))]
#[allow(dead_code)]
fn parse_address(addr: &str) -> (String, String) {
    if let Some(rest) = addr.strip_prefix("udp://") {
        return ("udp".into(), rest.to_string());
    }
    if let Some(rest) = addr.strip_prefix("https://") {
        let host = rest.split('/').next().unwrap_or(rest);
        return ("https".into(), host.to_string());
    }
    if let Some(rest) = addr.strip_prefix("rcode://") {
        return ("rcode".into(), rest.to_string());
    }
    ("other".into(), addr.to_string())
}

#[cfg(any(test, feature = "dev-cli"))]
#[allow(dead_code)]
fn fold_rule_singletons(r: &Value) -> Value {
    if let Some(obj) = r.as_object() {
        let mut m = obj.clone();
        for k in ["domain_suffix", "geosite", "protocol"] {
            if let Some(Value::Array(a)) = m.get(k) {
                if a.len() == 1 {
                    m.insert(k.into(), a[0].clone());
                }
            }
        }
        return Value::Object(m);
    }
    r.clone()
}

#[cfg(any(test, feature = "dev-cli"))]
#[allow(dead_code)]
fn insert_non_empty_val(root: &mut Map<String, Value>, k: &str, v: &Option<Value>) {
    if let Some(Value::Object(m)) = v {
        if !m.is_empty() {
            root.insert(k.into(), Value::Object(m.clone()));
        }
    }
}
#[cfg(any(test, feature = "dev-cli"))]
#[allow(clippy::ptr_arg)]
#[allow(dead_code)]
fn insert_non_empty_arr(root: &mut Map<String, Value>, k: &str, v: &Vec<Value>) {
    if !v.is_empty() {
        root.insert(k.into(), Value::Array(v.clone()));
    }
}

/// 若 DNS server 未被规则引用，则移除（更贴近 sing-box format）
#[cfg(any(test, feature = "dev-cli"))]
#[allow(dead_code)]
fn prune_unused_dns_servers(root: &mut Map<String, Value>) {
    use std::collections::HashSet;
    let mut used: HashSet<String> = HashSet::new();
    if let Some(rules) = root
        .get("dns")
        .and_then(|x| x.get("rules"))
        .and_then(|x| x.as_array())
    {
        for r in rules {
            if let Some(srv) = r.get("server").and_then(|x| x.as_str()) {
                used.insert(srv.to_string());
            }
        }
    }
    // If no servers are referenced by rules, do not prune anything.
    if used.is_empty() {
        return;
    }
    if let Some(servers) = root
        .get_mut("dns")
        .and_then(|x| x.get_mut("servers"))
        .and_then(|x| x.as_array_mut())
    {
        servers.retain(|s| {
            s.get("tag")
                .and_then(|t| t.as_str())
                .map(|tag| used.contains(tag))
                .unwrap_or(true)
        });
    }
}

/// 将 route.rules[*].protocol 的单元素数组折叠为标量
#[cfg(any(test, feature = "dev-cli"))]
#[allow(dead_code)]
fn fold_route_protocol_singletons(root: &mut Map<String, Value>) {
    if let Some(rules) = root
        .get_mut("route")
        .and_then(|x| x.get_mut("rules"))
        .and_then(|x| x.as_array_mut())
    {
        for r in rules {
            if let Some(obj) = r.as_object_mut() {
                if let Some(Value::Array(a)) = obj.get("protocol") {
                    if a.len() == 1 {
                        obj.insert("protocol".into(), a[0].clone());
                    }
                }
            }
        }
    }
}

/// 删除空的 inbounds/*/users
#[cfg(any(test, feature = "dev-cli"))]
#[allow(dead_code)]
fn prune_empty_inbound_users(root: &mut Map<String, Value>) {
    if let Some(inbounds) = root.get_mut("inbounds").and_then(|x| x.as_array_mut()) {
        for ib in inbounds {
            if let Some(obj) = ib.as_object_mut() {
                if let Some(Value::Array(a)) = obj.get("users") {
                    if a.is_empty() {
                        obj.remove("users");
                    }
                }
            }
        }
    }
}
