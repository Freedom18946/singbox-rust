//! Adapter Bridge: assembles protocol implementations from adapter registries.
//!
//! Missing builders are fatal startup errors. No protocol fallback exists in sb-core.

use crate::adapter::registry;
use crate::adapter::{AnyTlsUserParam, Bridge, InboundParam, OutboundParam};
use crate::context::Context;
use crate::endpoint::{endpoint_registry, Endpoint, EndpointAsOutbound, EndpointContext};
use crate::outbound::{OutboundImpl, OutboundRegistry, OutboundRegistryHandle};

use crate::router::{RouterHandle, RouterIndex};
use crate::service::{service_registry, ServiceContext};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use sb_config::ir::{ConfigIR, InboundIR, OutboundIR, OutboundType, RuleSetIR};
use std::sync::Arc;
use std::time::Duration;

fn outbound_registry_from_bridge(br: &Bridge) -> OutboundRegistry {
    let mut reg = OutboundRegistry::default();
    for (name, _kind, conn) in &br.outbounds {
        reg.insert(name.clone(), OutboundImpl::Connector(conn.clone()));
    }
    reg
}

fn outbound_registry_handle_from_bridge(br: &Bridge) -> Arc<OutboundRegistryHandle> {
    Arc::new(OutboundRegistryHandle::new(outbound_registry_from_bridge(
        br,
    )))
}

fn refresh_outbound_registry_handle(handle: &OutboundRegistryHandle, br: &Bridge) {
    handle.replace(outbound_registry_from_bridge(br));
}

fn add_endpoint_with_outbound(br: &mut Bridge, endpoint: Arc<dyn Endpoint>) {
    let tag = endpoint.tag().to_string();
    if tag.trim().is_empty() {
        br.startup_errors.push(format!(
            "{} endpoint has an empty tag and cannot be exposed as an outbound",
            endpoint.endpoint_type()
        ));
        tracing::error!(
            target: "sb_core::adapter",
            endpoint_type = %endpoint.endpoint_type(),
            "endpoint tag is empty; refusing endpoint-as-outbound registration"
        );
        return;
    }

    if br.endpoints.iter().any(|existing| existing.tag() == tag) {
        br.startup_errors
            .push(format!("duplicate endpoint tag '{tag}'"));
        tracing::error!(
            target: "sb_core::adapter",
            endpoint = %tag,
            endpoint_type = %endpoint.endpoint_type(),
            "duplicate endpoint tag; refusing endpoint registration"
        );
        return;
    }

    if br.outbounds.iter().any(|(name, _, _)| name == &tag) {
        br.startup_errors.push(format!(
            "endpoint tag '{tag}' conflicts with an outbound tag"
        ));
        tracing::error!(
            target: "sb_core::adapter",
            endpoint = %tag,
            endpoint_type = %endpoint.endpoint_type(),
            "endpoint tag conflicts with existing outbound tag; refusing endpoint-as-outbound registration"
        );
        return;
    }

    let kind = format!("endpoint/{}", endpoint.endpoint_type());
    let connector: Arc<dyn sb_types::Outbound> =
        Arc::new(EndpointAsOutbound::new(tag.clone(), endpoint.clone()));
    br.add_outbound(tag.clone(), kind, connector);
    br.add_endpoint(endpoint);
}

fn install_runtime_inbound_handle(br: &Bridge) {
    let tagged = br
        .inbounds
        .iter()
        .cloned()
        .zip(br.inbound_tags.iter().cloned())
        .filter_map(|(service, tag)| tag.map(|tag| (tag, service)))
        .collect();
    registry::install_runtime_inbounds(Arc::new(registry::InboundRegistryHandle::new(tagged)));
}

pub fn publish_runtime_registries(br: &Bridge) {
    registry::install_runtime_outbounds(outbound_registry_handle_from_bridge(br));
    install_runtime_inbound_handle(br);
}

fn router_handle_from_ir(
    cfg: &ConfigIR,
    runtime_options: Arc<crate::runtime_options::RouterRuntimeOptions>,
) -> Result<Arc<RouterHandle>, String> {
    let idx = crate::router::builder::build_index_from_ir(cfg)
        .map_err(|error| format!("router index build failed: {error}"))?;
    let db = build_local_rule_set_db(cfg)?;
    build_router_handle(cfg, runtime_options, idx, db)
}

fn rule_set_format(
    rule_set: &RuleSetIR,
    source: &str,
) -> Result<crate::router::ruleset::RuleSetFormat, String> {
    let source_path = source.split(['?', '#']).next().unwrap_or(source);
    match rule_set.format.as_str() {
        "source" | "json" | "headless" => Ok(crate::router::ruleset::RuleSetFormat::Source),
        "binary" => Ok(crate::router::ruleset::RuleSetFormat::Binary),
        "" if source_path.ends_with(".srs") => Ok(crate::router::ruleset::RuleSetFormat::Binary),
        "" if source_path.ends_with(".json") => Ok(crate::router::ruleset::RuleSetFormat::Source),
        "" => Err(format!(
            "rule-set format is required when source has no .json or .srs extension: {source}"
        )),
        other => Err(format!("unknown rule-set format: {other}")),
    }
}

fn effective_remote_rule_set_detour<'a>(
    cfg: &'a ConfigIR,
    rule_set: &'a RuleSetIR,
) -> Option<&'a str> {
    rule_set
        .download_detour
        .as_deref()
        .filter(|detour| !detour.is_empty())
        .or(cfg
            .route
            .default_rule_set_download_detour
            .as_deref()
            .filter(|detour| !detour.is_empty()))
        .or(cfg
            .route
            .final_outbound
            .as_deref()
            .filter(|detour| !detour.is_empty()))
        .or(cfg
            .route
            .default
            .as_deref()
            .filter(|detour| !detour.is_empty()))
        .or_else(|| {
            cfg.outbounds
                .first()
                .map(|outbound| outbound.name.as_deref().unwrap_or(outbound.ty.ty_str()))
        })
}

fn validate_remote_rule_set_detour(cfg: &ConfigIR, rule_set: &RuleSetIR) -> Result<(), String> {
    let detour = effective_remote_rule_set_detour(cfg, rule_set);
    let Some(detour) = detour else {
        return Ok(());
    };
    let outbound = cfg
        .outbounds
        .iter()
        .find(|outbound| outbound.name.as_deref().unwrap_or(outbound.ty.ty_str()) == detour)
        .ok_or_else(|| {
            format!(
                "remote rule set '{}' download_detour '{detour}' does not name an outbound",
                rule_set.tag
            )
        })?;
    if outbound.ty != OutboundType::Direct {
        return Err(format!(
            "remote rule set '{}' download_detour '{detour}' uses unsupported outbound type '{}'; only direct is supported by the runtime HTTP client",
            rule_set.tag,
            outbound.ty.ty_str()
        ));
    }
    Ok(())
}

fn add_local_rule_set(
    db: &crate::router::rule_set::RuleSetDb,
    rule_set: &RuleSetIR,
) -> Result<(), String> {
    let path = rule_set
        .path
        .as_deref()
        .ok_or_else(|| format!("local rule set '{}' is missing path", rule_set.tag))?;
    let format = match rule_set_format(rule_set, path)? {
        crate::router::ruleset::RuleSetFormat::Binary => "binary",
        crate::router::ruleset::RuleSetFormat::Source => "source",
    };
    db.add_rule_set(rule_set.tag.clone(), path, format)
        .map_err(|error| {
            format!(
                "failed to load local rule set '{}' from '{}': {error}",
                rule_set.tag, path
            )
        })
}

fn build_local_rule_set_db(
    cfg: &ConfigIR,
) -> Result<Option<Arc<crate::router::rule_set::RuleSetDb>>, String> {
    if cfg.route.rule_set.is_empty() {
        return Ok(None);
    }
    let db = crate::router::rule_set::RuleSetDb::new();
    for rule_set in &cfg.route.rule_set {
        match rule_set.ty.as_str() {
            "inline" | "" => {
                return Err(format!(
                    "inline rule set '{}' is not supported by the runtime router",
                    rule_set.tag
                ));
            }
            "local" => add_local_rule_set(&db, rule_set)?,
            "remote" => {
                let url = rule_set
                    .url
                    .as_deref()
                    .ok_or_else(|| format!("remote rule set '{}' is missing url", rule_set.tag))?;
                rule_set_format(rule_set, url)?;
                validate_remote_rule_set_detour(cfg, rule_set)?;
            }
            other => {
                return Err(format!(
                    "unsupported rule-set type '{other}' for '{}'",
                    rule_set.tag
                ));
            }
        }
    }
    Ok(Some(Arc::new(db)))
}

async fn build_remote_rule_set_db(
    cfg: &ConfigIR,
    context: &Context,
) -> Result<Option<Arc<crate::router::rule_set::RuleSetDb>>, String> {
    if cfg.route.rule_set.is_empty() {
        return Ok(None);
    }
    let db = crate::router::rule_set::RuleSetDb::new();
    let cache_dir = std::env::temp_dir().join(format!(
        "singbox-rust-rule-set-cache-{}",
        std::process::id()
    ));
    for rule_set in &cfg.route.rule_set {
        match rule_set.ty.as_str() {
            "inline" | "" => {
                return Err(format!(
                    "inline rule set '{}' is not supported by the runtime router",
                    rule_set.tag
                ));
            }
            "local" => add_local_rule_set(&db, rule_set)?,
            "remote" => {
                let url = rule_set
                    .url
                    .as_deref()
                    .ok_or_else(|| format!("remote rule set '{}' is missing url", rule_set.tag))?;
                let format = rule_set_format(rule_set, url)?;
                validate_remote_rule_set_detour(cfg, rule_set)?;
                let mut manager = crate::router::ruleset::RuleSetManager::new(
                    cache_dir.clone(),
                    Duration::from_secs(3600),
                );
                if let Some(cache_file) = context.cache_file.clone() {
                    manager = manager.with_cache_file(cache_file);
                }
                let loaded = manager
                    .load(
                        rule_set.tag.clone(),
                        crate::router::ruleset::RuleSetSource::Remote(url.to_string()),
                        format,
                    )
                    .await
                    .map_err(|error| {
                        format!(
                            "failed to download remote rule set '{}' from '{}': {error}",
                            rule_set.tag, url
                        )
                    })?;
                db.add_compiled_rule_set(rule_set.tag.clone(), loaded);
            }
            other => {
                return Err(format!(
                    "unsupported rule-set type '{other}' for '{}'",
                    rule_set.tag
                ));
            }
        }
    }
    Ok(Some(Arc::new(db)))
}

fn build_router_handle(
    cfg: &ConfigIR,
    runtime_options: Arc<crate::runtime_options::RouterRuntimeOptions>,
    idx: Arc<RouterIndex>,
    rule_set_db: Option<Arc<crate::router::rule_set::RuleSetDb>>,
) -> Result<Arc<RouterHandle>, String> {
    let mut handle = RouterHandle::from_index_with_options(idx, runtime_options);
    if let Some(db) = rule_set_db {
        handle = handle.with_rule_set_db(db);
    }
    if let Some(path) = &cfg.route.geoip_path {
        handle = handle.with_geoip_file(path).map_err(|error| {
            format!("failed to load GeoIP database from route.geoip_path '{path}': {error}")
        })?;
    }
    if let Some(path) = &cfg.route.geosite_path {
        handle = handle.with_geosite_file(path).map_err(|error| {
            format!("failed to load Geosite database from route.geosite_path '{path}': {error}")
        })?;
    }
    Ok(Arc::new(handle))
}

async fn router_handle_from_ir_async(
    cfg: &ConfigIR,
    runtime_options: Arc<crate::runtime_options::RouterRuntimeOptions>,
    context: &Context,
) -> Result<Arc<RouterHandle>, String> {
    let idx = crate::router::builder::build_index_from_ir(cfg)
        .map_err(|error| format!("router index build failed: {error}"))?;
    let db = build_remote_rule_set_db(cfg, context).await?;
    build_router_handle(cfg, runtime_options, idx, db)
}

#[allow(dead_code)]
fn ir_to_router_rules_text(cfg: &ConfigIR) -> String {
    fn rule_outbound(rule: &sb_config::ir::RuleIR, cfg: &ConfigIR) -> String {
        rule.outbound
            .clone()
            .or_else(|| cfg.route.default.clone())
            .or_else(|| cfg.route.final_outbound.clone())
            .unwrap_or_else(|| "unresolved".to_string())
    }

    let mut rules = Vec::new();
    for rule in &cfg.route.rules {
        let outbound = rule_outbound(rule, cfg);
        for domain in &rule.domain {
            rules.push(format!("domain:{domain}={outbound}"));
        }
        for suffix in &rule.domain_suffix {
            rules.push(format!("domain_suffix:{suffix}={outbound}"));
        }
        for keyword in &rule.domain_keyword {
            rules.push(format!("domain_keyword:{keyword}={outbound}"));
        }
        for regex in &rule.domain_regex {
            rules.push(format!("domain_regex:{regex}={outbound}"));
        }
        for geosite in &rule.geosite {
            rules.push(format!("geosite:{geosite}={outbound}"));
        }
        for geoip in &rule.geoip {
            rules.push(format!("geoip:{geoip}={outbound}"));
        }
        for ipcidr in &rule.ipcidr {
            let kind = if ipcidr.contains(':') {
                "cidr6"
            } else {
                "cidr4"
            };
            rules.push(format!("{kind}:{ipcidr}={outbound}"));
        }
        for port in &rule.port {
            if port.contains('-') {
                rules.push(format!("portrange:{port}={outbound}"));
            } else {
                rules.push(format!("port:{port}={outbound}"));
            }
        }
        for process in &rule.process_name {
            rules.push(format!("process:{process}={outbound}"));
        }
        for process_path in &rule.process_path {
            rules.push(format!("process_path:{process_path}={outbound}"));
        }
        for wifi_ssid in &rule.wifi_ssid {
            rules.push(format!("wifi_ssid:{wifi_ssid}={outbound}"));
        }
        for wifi_bssid in &rule.wifi_bssid {
            rules.push(format!("wifi_bssid:{wifi_bssid}={outbound}"));
        }
        for rule_set in &rule.rule_set {
            rules.push(format!("rule_set:{rule_set}={outbound}"));
        }
        for rule_set_ip in &rule.rule_set_ipcidr {
            rules.push(format!("rule_set_ip:{rule_set_ip}={outbound}"));
        }
        for uid in &rule.user_id {
            rules.push(format!("uid:{uid}={outbound}"));
        }
        for user in &rule.user {
            rules.push(format!("user:{user}={outbound}"));
        }
        for gid in &rule.group_id {
            rules.push(format!("gid:{gid}={outbound}"));
        }
        for group in &rule.group {
            rules.push(format!("group:{group}={outbound}"));
        }
        for source in &rule.source {
            rules.push(format!("source:{source}={outbound}"));
        }
        for dest in &rule.dest {
            rules.push(format!("dest:{dest}={outbound}"));
        }
        for user_agent in &rule.user_agent {
            rules.push(format!("user_agent:{user_agent}={outbound}"));
        }
        for network in &rule.network {
            rules.push(format!("transport:{network}={outbound}"));
        }
        for protocol in &rule.protocol {
            rules.push(format!("protocol:{protocol}={outbound}"));
        }
    }

    // Use 'default' or 'final_outbound' as the final fallback rule
    let final_rule = cfg
        .route
        .default
        .as_ref()
        .or(cfg.route.final_outbound.as_ref())
        .map(|s| s.as_str())
        .unwrap_or("unresolved");
    rules.push(format!("default={final_rule}"));

    rules.join("\n")
}

fn parse_optional_inbound_duration(
    protocol: &str,
    listen: &str,
    field: &str,
    value: Option<&str>,
) -> anyhow::Result<Option<std::time::Duration>> {
    value
        .map(|raw| {
            humantime::parse_duration(raw).map_err(|err| {
                anyhow::anyhow!(
                    "{protocol} inbound {field} '{raw}' is invalid for listen '{listen}'; silent duration fallback is disabled; fix the config explicitly: {err}"
                )
            })
        })
        .transpose()
}

fn parse_optional_outbound_duration(
    protocol: &str,
    outbound: &str,
    field: &str,
    value: Option<&str>,
) -> anyhow::Result<Option<std::time::Duration>> {
    value
        .map(|raw| {
            humantime::parse_duration(raw).map_err(|err| {
                anyhow::anyhow!(
                    "{protocol} outbound {field} '{raw}' is invalid for outbound '{outbound}'; silent duration fallback is disabled; fix the config explicitly: {err}"
                )
            })
        })
        .transpose()
}

fn parse_optional_outbound_ipv4_addr(
    protocol: &str,
    outbound: &str,
    field: &str,
    value: Option<&str>,
) -> anyhow::Result<Option<std::net::Ipv4Addr>> {
    value
        .map(|raw| {
            raw.parse::<std::net::Ipv4Addr>().map_err(|err| {
                anyhow::anyhow!(
                    "{protocol} outbound {field} '{raw}' is invalid for outbound '{outbound}'; silent IP parse fallback is disabled; fix the config explicitly: {err}"
                )
            })
        })
        .transpose()
}

fn parse_optional_outbound_ipv6_addr(
    protocol: &str,
    outbound: &str,
    field: &str,
    value: Option<&str>,
) -> anyhow::Result<Option<std::net::Ipv6Addr>> {
    value
        .map(|raw| {
            raw.parse::<std::net::Ipv6Addr>().map_err(|err| {
                anyhow::anyhow!(
                    "{protocol} outbound {field} '{raw}' is invalid for outbound '{outbound}'; silent IP parse fallback is disabled; fix the config explicitly: {err}"
                )
            })
        })
        .transpose()
}

/// Converts inbound IR to adapter parameter.
fn to_inbound_param(
    ib: &InboundIR,
    conn_tracker: Arc<sb_common::conntrack::ConnTracker>,
) -> anyhow::Result<InboundParam> {
    let users_anytls = ib.users_anytls.as_ref().map(|users| {
        users
            .iter()
            .map(|user| AnyTlsUserParam {
                name: user.name.clone(),
                password: user.password.clone(),
            })
            .collect()
    });

    // Serialize Hysteria2 users to JSON if present
    let users_hysteria2 = ib
        .users_hysteria2
        .as_ref()
        .map(|users| serde_json::to_string(users).unwrap_or_else(|_| "[]".to_string()));

    // Serialize TUIC users to JSON if present
    let users_tuic = ib
        .users_tuic
        .as_ref()
        .map(|users| serde_json::to_string(users).unwrap_or_else(|_| "[]".to_string()));

    // Serialize Hysteria v1 users to JSON if present
    let users_hysteria = ib
        .users_hysteria
        .as_ref()
        .map(|users| serde_json::to_string(users).unwrap_or_else(|_| "[]".to_string()));

    // Serialize Trojan users to JSON if present
    let users_trojan = ib
        .users_trojan
        .as_ref()
        .map(|users| serde_json::to_string(users).unwrap_or_else(|_| "[]".to_string()));

    let users_shadowtls = ib
        .users_shadowtls
        .as_ref()
        .map(|users| serde_json::to_string(users).unwrap_or_else(|_| "[]".to_string()));

    let shadowtls_handshake = ib
        .shadowtls_handshake
        .as_ref()
        .map(|cfg| serde_json::to_string(cfg).unwrap_or_else(|_| "{}".to_string()));

    let shadowtls_handshake_for_server_name = ib
        .shadowtls_handshake_for_server_name
        .as_ref()
        .map(|cfg| serde_json::to_string(cfg).unwrap_or_else(|_| "{}".to_string()));

    // Serialize VLESS users to JSON if present
    let users_vless = ib
        .users_vless
        .as_ref()
        .map(|users| serde_json::to_string(users).unwrap_or_else(|_| "[]".to_string()));

    // Serialize VMess users to JSON if present
    let users_vmess = ib
        .users_vmess
        .as_ref()
        .map(|users| serde_json::to_string(users).unwrap_or_else(|_| "[]".to_string()));

    // Serialize Shadowsocks users to JSON if present
    let users_shadowsocks = ib
        .users_shadowsocks
        .as_ref()
        .map(|users| serde_json::to_string(users).unwrap_or_else(|_| "[]".to_string()));

    // Serialize Hysteria2 masquerade to JSON if present
    let masquerade = ib
        .masquerade
        .as_ref()
        .map(|m| serde_json::to_string(m).unwrap_or_else(|_| "{}".to_string()));

    // Serialize Tun options to JSON if present
    let tun_options = ib
        .tun
        .as_ref()
        .map(|t| serde_json::to_string(t).unwrap_or_else(|_| "{}".to_string()));

    let listen = format!("{}:{}", ib.listen, ib.port);
    let udp_timeout = parse_optional_inbound_duration(
        ib.ty.ty_str(),
        &listen,
        "udp_timeout",
        ib.udp_timeout.as_deref(),
    )?;

    Ok(InboundParam {
        kind: ib.ty.ty_str().to_string(),
        tag: ib.tag.clone(),
        listen: ib.listen.clone(),
        port: ib.port,
        basic_auth: ib.basic_auth.clone(),
        users: ib
            .users
            .clone()
            .or_else(|| ib.basic_auth.clone().map(|user| vec![user])),
        sniff: ib.sniff,
        sniff_override_destination: ib.sniff_override_destination,
        udp: ib.udp,
        override_host: ib.override_host.clone(),
        override_port: ib.override_port,
        network: ib.network.clone(),
        users_anytls,
        password: ib.password.clone(),
        uuid: ib.uuid.clone(),
        method: ib.method.clone(),
        security: ib.security.clone(),
        flow: ib.flow.clone(),
        transport: ib.transport.clone(),
        ws_path: ib.ws_path.clone(),
        ws_host: ib.ws_host.clone(),
        grpc_service: ib.grpc_service.clone(),
        grpc_method: ib.grpc_method.clone(),
        grpc_metadata: ib.grpc_metadata.clone(),
        http_upgrade_path: ib.http_upgrade_path.clone(),
        http_upgrade_host: ib.http_upgrade_host.clone(),
        http_upgrade_headers: ib.http_upgrade_headers.clone(),
        anytls_padding: ib.anytls_padding.clone(),
        tls_cert_path: ib.tls_cert_path.clone(),
        tls_key_path: ib.tls_key_path.clone(),
        tls_cert_pem: ib.tls_cert_pem.clone(),
        tls_key_pem: ib.tls_key_pem.clone(),
        tls_server_name: ib.tls_server_name.clone(),
        tls_alpn: ib.tls_alpn.clone(),
        tls: ib.tls.clone(),
        reality: ib.reality.clone(),
        users_hysteria2,
        congestion_control: ib.congestion_control.clone(),
        salamander: ib.salamander.clone(),
        obfs: ib.obfs.clone(),
        masquerade,
        brutal_up_mbps: ib.brutal_up_mbps,
        brutal_down_mbps: ib.brutal_down_mbps,
        tun_options,
        users_tuic,
        users_hysteria,
        hysteria_protocol: ib.hysteria_protocol.clone(),
        hysteria_obfs: ib.hysteria_obfs.clone(),
        hysteria_up_mbps: ib.hysteria_up_mbps,
        hysteria_down_mbps: ib.hysteria_down_mbps,
        hysteria_recv_window_conn: ib.hysteria_recv_window_conn,
        hysteria_recv_window: ib.hysteria_recv_window,
        multiplex: ib.multiplex.clone(),
        users_trojan,
        shadowtls_version: ib.version,
        users_shadowtls,
        shadowtls_handshake,
        shadowtls_handshake_for_server_name,
        shadowtls_strict_mode: ib.shadowtls_strict_mode,
        shadowtls_wildcard_sni: ib.shadowtls_wildcard_sni.clone(),
        users_vless,
        users_vmess,
        users_shadowsocks,
        udp_timeout,
        detour: ib.detour.clone(),
        domain_strategy: ib.domain_strategy.clone(),
        set_system_proxy: ib.set_system_proxy,
        allow_private_network: ib.allow_private_network,
        conn_tracker,
        ssh_host_key_path: ib.ssh_host_key_path.clone(),
    })
}

/// Converts outbound IR to (name, parameter) tuple.
///
/// The name defaults to the outbound type string if not explicitly provided.
fn to_outbound_param(ob: &OutboundIR) -> anyhow::Result<(String, OutboundParam)> {
    let name = ob.name.clone().unwrap_or_else(|| ob.ty_str().to_string());
    let kind = ob.ty.ty_str().to_string();
    let connect_timeout = parse_optional_outbound_duration(
        ob.ty.ty_str(),
        &name,
        "connect_timeout",
        ob.connect_timeout.as_deref(),
    )?;
    let inet4_bind_address = parse_optional_outbound_ipv4_addr(
        ob.ty.ty_str(),
        &name,
        "inet4_bind_address",
        ob.inet4_bind_address.as_deref(),
    )?;
    let inet6_bind_address = parse_optional_outbound_ipv6_addr(
        ob.ty.ty_str(),
        &name,
        "inet6_bind_address",
        ob.inet6_bind_address.as_deref(),
    )?;
    Ok((
        name,
        OutboundParam {
            kind,
            name: ob.name.clone(),
            server: ob.server.clone(),
            port: ob.port,
            credentials: ob.credentials.clone(),
            uuid: ob.uuid.clone(),
            token: ob.token.clone(),
            password: ob.password.clone(),
            congestion_control: ob.congestion_control.clone(),
            alpn: ob
                .alpn
                .clone()
                .or_else(|| ob.tls_alpn.as_ref().map(|v| v.join(","))),
            skip_cert_verify: ob.skip_cert_verify,
            udp_relay_mode: ob.udp_relay_mode.clone(),
            udp_over_stream: ob.udp_over_stream,
            ssh_private_key: ob
                .ssh_private_key
                .clone()
                .or(ob.ssh_private_key_path.clone()),
            ssh_private_key_passphrase: ob.ssh_private_key_passphrase.clone(),
            ssh_host_key_verification: ob.ssh_host_key_verification,
            ssh_known_hosts_path: ob.ssh_known_hosts_path.clone(),
            bind_interface: ob.bind_interface.clone(),
            inet4_bind_address,
            inet6_bind_address,
            routing_mark: ob.routing_mark,
            reuse_addr: ob.reuse_addr,
            connect_timeout,
            tcp_fast_open: ob.tcp_fast_open,
            tcp_multi_path: ob.tcp_multi_path,
            udp_fragment: ob.udp_fragment,
            domain_strategy: ob.domain_strategy.clone(),
            multiplex: ob.multiplex.clone(),
        },
    ))
}

/// Attempts to create an inbound service using the adapter registry (when feature enabled).
///
/// Supplies adapter builders with runtime context (engine/bridge) so they can wire routing.
fn try_adapter_inbound(
    p: &InboundParam,
    ctx: &registry::AdapterInboundContext,
) -> Option<Arc<dyn sb_types::Inbound>> {
    if let Some(builder) = registry::get_inbound(&p.kind) {
        return builder(p, ctx);
    }
    None
}

/// Attempts to create an outbound connector using the adapter registry (when feature enabled).
/// Supplies adapter builders with runtime context (bridge) so they can resolve dependencies.
fn try_adapter_outbound(p: &OutboundParam, ob: &OutboundIR, br: &Bridge) -> Option<BuiltOutbound> {
    if let Some(builder) = registry::get_outbound(&p.kind) {
        let ctx = registry::AdapterOutboundContext {
            bridge: Arc::new(br.clone()),
            context: crate::context::ContextRegistry::from(&br.context),
        };
        if let Some(outbound) = builder(p, ob, &ctx) {
            return Some(BuiltOutbound { outbound });
        }
    }
    None
}

struct BuiltOutbound {
    outbound: Arc<dyn sb_types::Outbound>,
}

fn unavailable_protocol_error(direction: &str, kind: &str, tag: &str) -> String {
    format!(
        "{direction} '{tag}' kind '{kind}' is unavailable: protocol is not compiled into this build or its adapter configuration was rejected"
    )
}

/// Helper: assembles basic outbounds (excluding selectors).
fn assemble_outbounds(cfg: &ConfigIR, br: &mut Bridge) {
    for ob in &cfg.outbounds {
        // Skip selector/urltest in first pass - they need all other outbounds registered first
        if ob.ty == OutboundType::Selector || ob.ty == OutboundType::UrlTest {
            continue;
        }

        let (name, p) = match to_outbound_param(ob) {
            Ok(p) => p,
            Err(err) => {
                let message = format!(
                    "outbound '{}' kind '{}' has invalid configuration: {err}",
                    ob.name.as_deref().unwrap_or(ob.ty_str()),
                    ob.ty.ty_str()
                );
                br.startup_errors.push(message.clone());
                tracing::error!(
                    target: "sb_core::adapter",
                    outbound = %ob.name.as_deref().unwrap_or(ob.ty_str()),
                    kind = %ob.ty.ty_str(),
                    error = %err,
                    message = %message,
                    "invalid outbound config; refusing to build adapter"
                );
                continue;
            }
        };
        let kind = p.kind.clone();

        if let Some(o) = try_adapter_outbound(&p, ob, br) {
            // Optionally wrap with circuit breaker
            let outbound = maybe_wrap_with_cb(
                name.as_str(),
                o.outbound,
                br.context.runtime_options.services.circuit_breaker_enabled,
            );
            br.add_outbound(name.clone(), kind, outbound);
        } else {
            let message = unavailable_protocol_error("outbound", &kind, &name);
            br.startup_errors.push(message.clone());
            tracing::error!(
                target: "sb_core::adapter",
                outbound = %name,
                kind = %kind,
                message = %message,
                "no outbound builder available for requested kind"
            );
        }
    }
}

// ============================================================================
// Optional Circuit Breaker wrapper for outbound connectors
// ============================================================================

static CB_STATES: Lazy<DashMap<String, i32>> = Lazy::new(DashMap::new);

/// Update circuit breaker state for an outbound (0=closed,1=half-open,2=open)
pub fn cb_state_set(name: &str, code: i32) {
    CB_STATES.insert(name.to_string(), code);
}

/// Snapshot current circuit breaker states
pub fn cb_state_snapshot() -> Vec<(String, i32)> {
    CB_STATES
        .iter()
        .map(|kv| (kv.key().clone(), *kv.value()))
        .collect()
}

#[cfg(feature = "v2ray_transport")]
#[derive(Clone)]
struct CbConnector {
    name: String,
    inner: Arc<dyn sb_types::Outbound>,
    cb: std::sync::Arc<sb_transport::circuit_breaker::CircuitBreaker>,
}

#[cfg(feature = "v2ray_transport")]
impl std::fmt::Debug for CbConnector {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CbConnector")
            .field("name", &self.name)
            .finish()
    }
}

#[cfg(feature = "v2ray_transport")]
impl sb_types::Outbound for CbConnector {
    fn r#type(&self) -> &str {
        self.inner.r#type()
    }

    fn tag(&self) -> sb_types::OutboundTag {
        self.inner.tag()
    }

    fn network(&self) -> &[sb_types::NetworkKind] {
        self.inner.network()
    }

    fn dependencies(&self) -> &[sb_types::OutboundTag] {
        self.inner.dependencies()
    }

    fn dial<'a>(
        &'a self,
        session: &'a sb_types::Session,
    ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedStream, sb_types::CoreError>> {
        Box::pin(async move {
            match self.cb.allow_request().await {
                sb_transport::circuit_breaker::CircuitBreakerDecision::Reject => {
                    return Err(sb_types::CoreError::policy("outbound circuit open"));
                }
                sb_transport::circuit_breaker::CircuitBreakerDecision::Allow => {}
            }

            let res = self.inner.dial(session).await;
            let is_timeout = matches!(res, Err(sb_types::CoreError::Timeout { .. }));
            self.cb.record_result(res.is_ok(), is_timeout).await;
            let code = match self.cb.state().await {
                sb_transport::circuit_breaker::CircuitState::Closed => 0,
                sb_transport::circuit_breaker::CircuitState::HalfOpen => 1,
                sb_transport::circuit_breaker::CircuitState::Open => 2,
            };
            crate::metrics::set_outbound_circuit_state(self.name.as_str(), code);
            cb_state_set(self.name.as_str(), code);
            res
        })
    }

    fn listen_packet<'a>(
        &'a self,
        session: &'a sb_types::Session,
    ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedPacketConn, sb_types::CoreError>> {
        self.inner.listen_packet(session)
    }
}

#[cfg(feature = "v2ray_transport")]
fn maybe_wrap_with_cb(
    name: &str,
    inner: Arc<dyn sb_types::Outbound>,
    enabled: bool,
) -> Arc<dyn sb_types::Outbound> {
    if !enabled {
        return inner;
    }
    let cb = sb_transport::circuit_breaker::CircuitBreaker::from_env(name.to_string());
    Arc::new(CbConnector {
        name: name.to_string(),
        inner,
        cb: std::sync::Arc::new(cb),
    })
}

#[cfg(not(feature = "v2ray_transport"))]
fn maybe_wrap_with_cb(
    _name: &str,
    inner: Arc<dyn sb_types::Outbound>,
    _enabled: bool,
) -> Arc<dyn sb_types::Outbound> {
    // Circuit breaker requires v2ray_transport feature
    inner
}

/// Helper: assembles selector outbounds with resolved members.
///
/// Second-pass processing to bind selector members after basic outbounds are registered.
fn assemble_selectors(cfg: &ConfigIR, br: &mut Bridge) {
    for ob in &cfg.outbounds {
        if ob.ty == OutboundType::Selector || ob.ty == OutboundType::UrlTest {
            let (name, p) = match to_outbound_param(ob) {
                Ok(p) => p,
                Err(err) => {
                    let message = format!(
                        "outbound '{}' kind '{}' has invalid configuration: {err}",
                        ob.name.as_deref().unwrap_or(ob.ty_str()),
                        ob.ty.ty_str()
                    );
                    br.startup_errors.push(message.clone());
                    tracing::error!(
                        target: "sb_core::adapter",
                        outbound = %ob.name.as_deref().unwrap_or(ob.ty_str()),
                        kind = %ob.ty.ty_str(),
                        error = %err,
                        message = %message,
                        "invalid outbound config; refusing to build adapter"
                    );
                    continue;
                }
            };
            let kind = p.kind.clone();

            if let Some(o) = try_adapter_outbound(&p, ob, br) {
                let outbound = maybe_wrap_with_cb(
                    name.as_str(),
                    o.outbound,
                    br.context.runtime_options.services.circuit_breaker_enabled,
                );
                br.add_outbound(name.clone(), kind, outbound);
            } else {
                let message = unavailable_protocol_error("outbound", &kind, &name);
                br.startup_errors.push(message.clone());
                tracing::error!(
                    target: "sb_core::adapter",
                    outbound = %name,
                    kind = %kind,
                    message = %message,
                    "no selector/urltest builder available for requested kind"
                );
            }
        }
    }
}

pub fn build_bridge(cfg: &ConfigIR, engine: crate::router::Engine, context: Context) -> Bridge {
    let router_options = Arc::new(context.runtime_options.router.clone());
    let router_result = router_handle_from_ir(cfg, router_options);
    build_bridge_with_router(cfg, engine, context, router_result)
}

/// Runtime bridge builder with asynchronous remote rule-set initialization.
/// Initial download failure is fatal, matching Go's `RemoteRuleSet.StartContext`.
pub async fn build_bridge_async(
    cfg: &ConfigIR,
    engine: crate::router::Engine,
    context: Context,
) -> Bridge {
    let router_options = Arc::new(context.runtime_options.router.clone());
    let router_result = router_handle_from_ir_async(cfg, router_options, &context).await;
    build_bridge_with_router(cfg, engine, context, router_result)
}

fn build_bridge_with_router(
    cfg: &ConfigIR,
    engine: crate::router::Engine,
    context: Context,
    router_result: Result<Arc<RouterHandle>, String>,
) -> Bridge {
    crate::endpoint::register_builtins();
    crate::services::register_builtins();
    let mut br = Bridge::new(context);
    let ctx_registry = crate::context::ContextRegistry::from(&br.context);

    // Initialize one shared RouterHandle for bridge, endpoints, and inbounds.
    let router_handle = match router_result {
        Ok(handle) => handle,
        Err(error) => {
            let message = format!("router configuration is invalid: {error}");
            br.startup_errors.push(message.clone());
            tracing::error!(
                target: "sb_core::adapter",
                error = %error,
                "router build failed; refusing runtime startup"
            );
            Arc::new(RouterHandle::from_options(Arc::new(
                br.context.runtime_options.router.clone(),
            )))
        }
    };
    br.router = Some(router_handle.clone());
    br.experimental = cfg.experimental.clone();

    // Step 1 & 2: Outbounds and selectors
    assemble_outbounds(cfg, &mut br);
    assemble_selectors(cfg, &mut br);
    // Extract dependency graph from IR (L2.9)
    br.outbound_deps = crate::outbound::manager::compute_outbound_deps(&cfg.outbounds);
    let outbound_handle = outbound_registry_handle_from_bridge(&br);

    let endpoint_handler = {
        let stats = br.context.v2ray_server.as_ref().and_then(|s| s.stats());
        Some(Arc::new(
            crate::endpoint::handler::EndpointConnectionHandler::new(
                router_handle.clone(),
                outbound_handle.clone(),
                stats,
            ),
        ))
    };

    // Step 3: Inbounds
    // Create shared connection manager for all inbounds (Go parity: route.ConnectionManager)
    let stats = br.context.v2ray_server.as_ref().and_then(|s| s.stats());
    let connection_manager = Arc::new(
        crate::router::RouteConnectionManager::new()
            .with_stats(stats)
            .with_conn_tracker(br.context.conn_tracker.clone())
            .with_public_suffix_list(
                br.context
                    .runtime_options
                    .router
                    .public_suffix_list
                    .as_deref(),
            ),
    );

    // Build DNS components for inbound context
    let (_, dns_router) = crate::dns::config_builder::build_dns_components_with_options(
        cfg,
        None,
        Arc::new(br.context.runtime_options.dns.clone()),
    )
    .ok()
    .unzip();
    let dns_router = dns_router.flatten(); // Option<Option<Arc>> -> Option<Arc>

    for ib in &cfg.inbounds {
        let p = match to_inbound_param(ib, br.context.conn_tracker.clone()) {
            Ok(p) => p,
            Err(err) => {
                let tag = ib.tag.as_deref().unwrap_or(ib.ty.ty_str());
                let message = format!(
                    "inbound '{tag}' kind '{}' has invalid configuration: {err}",
                    ib.ty.ty_str()
                );
                br.startup_errors.push(message.clone());
                tracing::error!(
                    target: "sb_core::adapter",
                    inbound = %ib.ty.ty_str(),
                    listen = %format!("{}:{}", ib.listen, ib.port),
                    error = %err,
                    message = %message,
                    "invalid inbound config; refusing to build adapter"
                );
                continue;
            }
        };
        let adapter_ctx = registry::AdapterInboundContext {
            engine: engine.clone(),
            bridge: Arc::new(br.clone()),
            outbounds: outbound_handle.clone(),
            router: router_handle.clone(),
            dns_router: dns_router.clone(),
            connection_manager: Some(connection_manager.clone()),
            context: ctx_registry.clone(),
        };

        if let Some(i) = try_adapter_inbound(&p, &adapter_ctx) {
            br.add_canonical_inbound_with_meta(p.kind.as_str(), p.tag.clone(), i);
        } else {
            let tag = p.tag.as_deref().unwrap_or(p.kind.as_str());
            let message = unavailable_protocol_error("inbound", &p.kind, tag);
            br.startup_errors.push(message.clone());
            tracing::error!(
                target: "sb_core::adapter",
                inbound = %p.kind,
                listen = %format!("{}:{}", p.listen, p.port),
                message = %message,
                "no inbound builder available for requested kind"
            );
        }
    }

    // Step 4: Endpoints
    for endpoint_ir in &cfg.endpoints {
        let ctx = EndpointContext::default();
        if let Some(endpoint) = endpoint_registry().build(endpoint_ir, &ctx) {
            if let Some(handler) = endpoint_handler.as_ref() {
                endpoint.set_connection_handler(handler.clone());
            }
            add_endpoint_with_outbound(&mut br, endpoint);
        } else {
            tracing::warn!(
                target: "sb_core::adapter",
                endpoint = %endpoint_ir.tag.as_deref().unwrap_or("unknown"),
                "endpoint builder not found"
            );
        }
    }
    refresh_outbound_registry_handle(&outbound_handle, &br);

    let endpoints_map: Arc<std::collections::HashMap<String, Arc<dyn crate::endpoint::Endpoint>>> =
        Arc::new(
            br.endpoints
                .iter()
                .map(|ep| (ep.tag().to_string(), ep.clone()))
                .collect(),
        );

    // Step 5: Services
    for service_ir in &cfg.services {
        let ctx = ServiceContext::default()
            .with_outbounds(outbound_handle.clone())
            .with_endpoints(endpoints_map.clone());
        let ctx = if let Some(router) = dns_router.clone() {
            // Prefer DNSRouter when available (DERP /bootstrap-dns, domain_resolver, etc.)
            ServiceContext {
                dns_router: Some(router),
                ..ctx
            }
        } else {
            ctx
        };
        if let Some(service) = service_registry().build(service_ir, &ctx) {
            br.add_service(service);
        } else {
            tracing::warn!(
                target: "sb_core::adapter",
                service = %service_ir.tag.as_deref().unwrap_or("unknown"),
                "service builder not found"
            );
        }
    }

    br
}

#[cfg(test)]
mod tests {
    use super::{
        add_endpoint_with_outbound, build_local_rule_set_db, outbound_registry_handle_from_bridge,
        parse_optional_inbound_duration, parse_optional_outbound_duration,
        parse_optional_outbound_ipv4_addr, parse_optional_outbound_ipv6_addr,
        router_handle_from_ir, rule_set_format, to_inbound_param, to_outbound_param,
    };
    use crate::endpoint::{Endpoint, StartStage};
    use sb_config::ir::{
        ConfigIR, InboundIR, InboundTlsOptionsIR, InboundType, OutboundIR, OutboundType, RuleSetIR,
    };
    use std::sync::Arc;

    #[derive(Debug)]
    struct DummyConnector;

    impl sb_types::Outbound for DummyConnector {
        fn r#type(&self) -> &str {
            "dummy"
        }
        fn tag(&self) -> sb_types::OutboundTag {
            sb_types::OutboundTag::new("dummy")
        }
        fn network(&self) -> &[sb_types::NetworkKind] {
            &[sb_types::NetworkKind::Tcp]
        }
        fn dial<'a>(
            &'a self,
            _session: &'a sb_types::Session,
        ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedStream, sb_types::CoreError>> {
            Box::pin(async {
                Err(sb_types::CoreError::connect(
                    sb_types::ConnectErrorKind::Unsupported,
                    "dummy connector",
                ))
            })
        }
        fn listen_packet<'a>(
            &'a self,
            _session: &'a sb_types::Session,
        ) -> sb_types::BoxFuture<'a, Result<sb_types::BoxedPacketConn, sb_types::CoreError>>
        {
            Box::pin(async {
                Err(sb_types::CoreError::connect(
                    sb_types::ConnectErrorKind::Unsupported,
                    "dummy connector",
                ))
            })
        }
    }

    #[derive(Debug)]
    struct DummyEndpoint {
        tag: String,
        endpoint_type: &'static str,
    }

    impl DummyEndpoint {
        fn new(tag: &str) -> Arc<Self> {
            Arc::new(Self {
                tag: tag.to_string(),
                endpoint_type: "wireguard",
            })
        }
    }

    impl Endpoint for DummyEndpoint {
        fn endpoint_type(&self) -> &str {
            self.endpoint_type
        }

        fn tag(&self) -> &str {
            &self.tag
        }

        fn start(
            &self,
            _stage: StartStage,
        ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }

        fn close(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
            Ok(())
        }
    }

    #[test]
    fn router_build_rejects_missing_local_rule_set() {
        let mut config = ConfigIR::default();
        config.route.rule_set.push(RuleSetIR {
            tag: "missing-local".to_string(),
            ty: "local".to_string(),
            format: "source".to_string(),
            path: Some("target/does-not-exist/routing-rule-set.json".to_string()),
            ..RuleSetIR::default()
        });

        let error = router_handle_from_ir(
            &config,
            Arc::new(crate::runtime_options::RouterRuntimeOptions::default()),
        )
        .expect_err("missing local rule set must reject router startup");

        assert!(error.contains("missing-local"), "unexpected error: {error}");
        assert!(
            error.contains("routing-rule-set.json"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn rule_set_format_uses_url_path_before_query() {
        let rule_set = RuleSetIR::default();
        assert_eq!(
            rule_set_format(&rule_set, "https://example.invalid/rules.srs?token=test").unwrap(),
            crate::router::ruleset::RuleSetFormat::Binary
        );
        assert_eq!(
            rule_set_format(&rule_set, "https://example.invalid/rules.json#published").unwrap(),
            crate::router::ruleset::RuleSetFormat::Source
        );
        assert!(rule_set_format(&rule_set, "https://example.invalid/rules").is_err());
    }

    #[test]
    fn router_build_rejects_inline_rule_set_instead_of_misrouting() {
        let mut config = ConfigIR::default();
        config.route.rule_set.push(RuleSetIR {
            tag: "inline-domains".to_string(),
            ty: String::new(),
            rules: Some(vec![sb_config::ir::RuleIR {
                domain: vec!["example.com".to_string()],
                ..sb_config::ir::RuleIR::default()
            }]),
            ..RuleSetIR::default()
        });

        let error = build_local_rule_set_db(&config)
            .expect_err("unsupported inline rule sets must not disappear from routing");
        assert!(
            error.contains("inline-domains"),
            "unexpected error: {error}"
        );
        assert!(error.contains("not supported"), "unexpected error: {error}");
    }

    #[test]
    fn remote_rule_set_rejects_non_direct_download_detour() {
        let mut config = ConfigIR::default();
        config.outbounds.push(OutboundIR {
            ty: OutboundType::Block,
            name: Some("blocked-download".to_string()),
            ..OutboundIR::default()
        });
        config.route.rule_set.push(RuleSetIR {
            tag: "remote".to_string(),
            ty: "remote".to_string(),
            format: "source".to_string(),
            url: Some("https://example.invalid/rules.json".to_string()),
            download_detour: Some("blocked-download".to_string()),
            ..RuleSetIR::default()
        });

        let error = router_handle_from_ir(
            &config,
            Arc::new(crate::runtime_options::RouterRuntimeOptions::default()),
        )
        .expect_err("unsupported rule-set detour must reject startup");

        assert!(
            error.contains("blocked-download"),
            "unexpected error: {error}"
        );
        assert!(error.contains("only direct"), "unexpected error: {error}");
    }

    #[test]
    fn remote_rule_set_uses_effective_default_download_detour() {
        let mut config = ConfigIR::default();
        config.outbounds.extend([
            OutboundIR {
                ty: OutboundType::Direct,
                name: Some("direct".to_string()),
                ..OutboundIR::default()
            },
            OutboundIR {
                ty: OutboundType::Block,
                name: Some("block".to_string()),
                ..OutboundIR::default()
            },
        ]);
        config.route.final_outbound = Some("block".to_string());
        config.route.rule_set.push(RuleSetIR {
            tag: "remote".to_string(),
            ty: "remote".to_string(),
            format: "source".to_string(),
            url: Some("https://example.invalid/rules.json".to_string()),
            ..RuleSetIR::default()
        });

        let error = router_handle_from_ir(
            &config,
            Arc::new(crate::runtime_options::RouterRuntimeOptions::default()),
        )
        .expect_err("implicit block default must not be treated as direct download");
        assert!(error.contains("block"), "unexpected error: {error}");
        assert!(error.contains("only direct"), "unexpected error: {error}");
    }

    #[tokio::test]
    async fn endpoint_registration_exposes_endpoint_tag_as_outbound() {
        let mut bridge = crate::adapter::Bridge::new(crate::context::Context::default());
        add_endpoint_with_outbound(&mut bridge, DummyEndpoint::new("wg-ep"));

        assert_eq!(bridge.endpoints.len(), 1);
        assert!(
            bridge
                .outbounds
                .iter()
                .any(|(tag, kind, _)| tag == "wg-ep" && kind == "endpoint/wireguard"),
            "endpoint tag should enter outbound namespace"
        );
        assert!(bridge.startup_errors.is_empty());

        let handle = outbound_registry_handle_from_bridge(&bridge);
        assert!(
            handle.resolve("wg-ep").is_some(),
            "refreshed registry handles should be able to see endpoint outbounds"
        );

        assert!(
            bridge.outbounds.iter().any(|(tag, _, _)| tag == "wg-ep"),
            "route.final endpoint tag should be present for supervisor default resolution"
        );
    }

    #[test]
    fn endpoint_registration_rejects_outbound_tag_conflict() {
        let mut bridge = crate::adapter::Bridge::new(crate::context::Context::default());
        bridge.add_outbound(
            "wg-ep".to_string(),
            "direct".to_string(),
            Arc::new(DummyConnector),
        );

        add_endpoint_with_outbound(&mut bridge, DummyEndpoint::new("wg-ep"));

        assert!(bridge.endpoints.is_empty());
        assert_eq!(bridge.outbounds.len(), 1);
        assert!(
            bridge
                .startup_errors
                .iter()
                .any(|error| error.contains("endpoint tag 'wg-ep' conflicts with an outbound tag")),
            "conflicts must be fatal and diagnostic: {:?}",
            bridge.startup_errors
        );
    }

    #[test]
    fn endpoint_registration_rejects_duplicate_endpoint_tag() {
        let mut bridge = crate::adapter::Bridge::new(crate::context::Context::default());
        add_endpoint_with_outbound(&mut bridge, DummyEndpoint::new("wg-ep"));
        add_endpoint_with_outbound(&mut bridge, DummyEndpoint::new("wg-ep"));

        assert_eq!(bridge.endpoints.len(), 1);
        assert_eq!(
            bridge
                .outbounds
                .iter()
                .filter(|(tag, _, _)| tag == "wg-ep")
                .count(),
            1
        );
        assert!(
            bridge
                .startup_errors
                .iter()
                .any(|error| error.contains("duplicate endpoint tag 'wg-ep'")),
            "second endpoint tag should be rejected before overwriting endpoint namespace: {:?}",
            bridge.startup_errors
        );
    }

    #[test]
    fn invalid_inbound_duration_is_rejected_explicitly() {
        let err =
            parse_optional_inbound_duration("mixed", "127.0.0.1:1080", "udp_timeout", Some("bad"))
                .expect_err("invalid duration should be rejected");
        let msg = err.to_string();
        assert!(msg.contains("mixed inbound udp_timeout 'bad' is invalid"));
        assert!(msg.contains("silent duration fallback is disabled"));
    }

    #[test]
    fn to_inbound_param_rejects_invalid_udp_timeout() {
        let ib = InboundIR {
            ty: InboundType::Mixed,
            listen: "127.0.0.1".to_string(),
            port: 1080,
            udp_timeout: Some("bad".to_string()),
            ..InboundIR::default()
        };

        let err = to_inbound_param(&ib, Arc::new(sb_common::conntrack::ConnTracker::new()))
            .expect_err("invalid duration should be rejected");
        assert!(err
            .to_string()
            .contains("mixed inbound udp_timeout 'bad' is invalid"));
    }

    #[test]
    fn to_inbound_param_preserves_typed_tls_options() {
        let tls = InboundTlsOptionsIR {
            enabled: true,
            server_name: Some("vmess.example".to_string()),
            alpn: Some(vec!["h2".to_string()]),
            min_version: Some("1.3".to_string()),
            max_version: Some("1.3".to_string()),
            certificate_path: Some("/tmp/vmess-cert.pem".to_string()),
            key_path: Some("/tmp/vmess-key.pem".to_string()),
            ..Default::default()
        };
        let ib = InboundIR {
            ty: InboundType::Vmess,
            listen: "127.0.0.1".to_string(),
            port: 443,
            tls: Some(tls.clone()),
            ..InboundIR::default()
        };

        let param = to_inbound_param(&ib, Arc::new(sb_common::conntrack::ConnTracker::new()))
            .expect("VMess inbound bridge");

        assert_eq!(param.tls, Some(tls));
    }

    #[test]
    fn invalid_outbound_duration_is_rejected_explicitly() {
        let err =
            parse_optional_outbound_duration("vmess", "edge-vmess", "connect_timeout", Some("bad"))
                .expect_err("invalid duration should be rejected");
        let msg = err.to_string();
        assert!(msg.contains("vmess outbound connect_timeout 'bad' is invalid"));
        assert!(msg.contains("silent duration fallback is disabled"));
    }

    #[test]
    fn to_outbound_param_rejects_invalid_connect_timeout() {
        let ob = OutboundIR {
            ty: OutboundType::Vmess,
            name: Some("edge-vmess".to_string()),
            connect_timeout: Some("bad".to_string()),
            ..OutboundIR::default()
        };

        let err = to_outbound_param(&ob).expect_err("invalid duration should be rejected");
        assert!(err
            .to_string()
            .contains("vmess outbound connect_timeout 'bad' is invalid"));
    }

    #[test]
    fn invalid_outbound_ipv4_addr_is_rejected_explicitly() {
        let err = parse_optional_outbound_ipv4_addr(
            "vmess",
            "edge-vmess",
            "inet4_bind_address",
            Some("bad"),
        )
        .expect_err("invalid ipv4 should be rejected");
        let msg = err.to_string();
        assert!(msg.contains("vmess outbound inet4_bind_address 'bad' is invalid"));
        assert!(msg.contains("silent IP parse fallback is disabled"));
    }

    #[test]
    fn invalid_outbound_ipv6_addr_is_rejected_explicitly() {
        let err = parse_optional_outbound_ipv6_addr(
            "vmess",
            "edge-vmess",
            "inet6_bind_address",
            Some("bad"),
        )
        .expect_err("invalid ipv6 should be rejected");
        let msg = err.to_string();
        assert!(msg.contains("vmess outbound inet6_bind_address 'bad' is invalid"));
        assert!(msg.contains("silent IP parse fallback is disabled"));
    }

    #[test]
    fn to_outbound_param_rejects_invalid_bind_address() {
        let ob = OutboundIR {
            ty: OutboundType::Vmess,
            name: Some("edge-vmess".to_string()),
            inet4_bind_address: Some("bad".to_string()),
            ..OutboundIR::default()
        };

        let err = to_outbound_param(&ob).expect_err("invalid bind address should be rejected");
        assert!(err
            .to_string()
            .contains("vmess outbound inet4_bind_address 'bad' is invalid"));
    }
}
