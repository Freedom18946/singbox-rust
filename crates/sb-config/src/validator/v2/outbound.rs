use sb_types::IssueCode;
use serde_json::Value;
use std::collections::HashSet;

use crate::ir::{ConfigIR, Credentials, HeaderEntry};

use super::{
    emit_issue, extract_string_list, insert_keys, object_keys, parse_millis_field,
    parse_seconds_field_to_millis, parse_u32_field,
};

const DEFAULT_URLTEST_URL: &str = "http://www.gstatic.com/generate_204";
const DEFAULT_URLTEST_INTERVAL_MS: u64 = 60_000;
const DEFAULT_URLTEST_TIMEOUT_MS: u64 = 5_000;
const DEFAULT_URLTEST_TOLERANCE_MS: u64 = 50;

fn allowed_outbound_keys() -> HashSet<String> {
    let mut set = object_keys(crate::ir::OutboundIR::default());
    if set.remove("ty") {
        set.insert("type".to_string());
    }
    set.insert("tag".to_string());
    insert_keys(
        &mut set,
        &[
            "transport",
            "ws",
            "h2",
            "tls",
            "http_upgrade",
            "httpupgrade",
            "grpc",
        ],
    );
    insert_keys(
        &mut set,
        &[
            "user",
            "auth_str",
            "url",
            "interval",
            "interval_ms",
            "timeout",
            "timeout_ms",
            "tolerance",
            "tolerance_ms",
            "outbounds",
            "default",
        ],
    );
    set
}

fn push_transport_token(tokens: &mut Vec<String>, token: &str) {
    let trimmed = token.trim();
    if trimmed.is_empty() {
        return;
    }
    let normalized = trimmed.to_ascii_lowercase();
    if !tokens
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(&normalized))
    {
        tokens.push(normalized);
    }
}

fn push_header_entry(target: &mut Vec<HeaderEntry>, key: &str, value: &str) {
    if key.trim().is_empty() {
        return;
    }
    target.push(HeaderEntry {
        key: key.trim().to_string(),
        value: value.to_string(),
    });
}

fn parse_header_entries(value: &Value, target: &mut Vec<HeaderEntry>) {
    match value {
        Value::Object(map) => {
            for (k, v) in map {
                if let Some(val) = v.as_str() {
                    push_header_entry(target, k, val);
                }
            }
        }
        Value::Array(arr) => {
            for item in arr {
                match item {
                    Value::Object(obj) => {
                        let name = obj
                            .get("name")
                            .or_else(|| obj.get("key"))
                            .and_then(|v| v.as_str());
                        let value = obj
                            .get("value")
                            .or_else(|| obj.get("val"))
                            .and_then(|v| v.as_str());
                        if let (Some(name), Some(value)) = (name, value) {
                            push_header_entry(target, name, value);
                        }
                    }
                    Value::Array(pair) => {
                        if pair.len() == 2 {
                            if let (Some(name), Some(value)) = (
                                pair.first().and_then(|v| v.as_str()),
                                pair.get(1).and_then(|v| v.as_str()),
                            ) {
                                push_header_entry(target, name, value);
                            }
                        }
                    }
                    Value::String(s) => {
                        if let Some((name, value)) = s.split_once('=') {
                            push_header_entry(target, name, value);
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
}

fn parse_transport_object(
    obj: &serde_json::Map<String, Value>,
    ob: &mut crate::ir::OutboundIR,
    tokens: &mut Vec<String>,
) {
    if let Some(ty) = obj.get("type").and_then(|v| v.as_str()) {
        push_transport_token(tokens, ty);
        match ty.trim().to_ascii_lowercase().as_str() {
            "ws" => {
                if ob.ws_path.is_none() {
                    ob.ws_path = obj
                        .get("path")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
                if ob.ws_host.is_none() {
                    if let Some(headers) = obj.get("headers").and_then(|v| v.as_object()) {
                        for (k, v) in headers {
                            if k.eq_ignore_ascii_case("host") {
                                if let Some(host) = v.as_str() {
                                    ob.ws_host = Some(host.to_string());
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            "h2" => {
                if ob.h2_path.is_none() {
                    ob.h2_path = obj
                        .get("path")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
                if ob.h2_host.is_none() {
                    ob.h2_host = obj
                        .get("host")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
            }
            "grpc" => {
                if ob.grpc_service.is_none() {
                    ob.grpc_service = obj
                        .get("service_name")
                        .or_else(|| obj.get("service"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
                if ob.grpc_method.is_none() {
                    ob.grpc_method = obj
                        .get("method_name")
                        .or_else(|| obj.get("method"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
                if ob.grpc_authority.is_none() {
                    ob.grpc_authority = obj
                        .get("authority")
                        .or_else(|| obj.get("host"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
                if let Some(meta_val) = obj.get("metadata") {
                    parse_header_entries(meta_val, &mut ob.grpc_metadata);
                }
            }
            "httpupgrade" | "http_upgrade" => {
                if ob.http_upgrade_path.is_none() {
                    ob.http_upgrade_path = obj
                        .get("path")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                }
                if let Some(headers_val) = obj.get("headers") {
                    parse_header_entries(headers_val, &mut ob.http_upgrade_headers);
                }
            }
            _ => {}
        }
    }
}

fn outbound_type_for(value: &Value) -> crate::ir::OutboundType {
    match value
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("unresolved")
    {
        "direct" => crate::ir::OutboundType::Direct,
        "http" => crate::ir::OutboundType::Http,
        "socks" => crate::ir::OutboundType::Socks,
        "block" => crate::ir::OutboundType::Block,
        "selector" => crate::ir::OutboundType::Selector,
        "urltest" => crate::ir::OutboundType::UrlTest,
        "shadowsocks" => crate::ir::OutboundType::Shadowsocks,
        "shadowtls" => crate::ir::OutboundType::Shadowtls,
        "hysteria2" => crate::ir::OutboundType::Hysteria2,
        "tuic" => crate::ir::OutboundType::Tuic,
        "vless" => crate::ir::OutboundType::Vless,
        "vmess" => crate::ir::OutboundType::Vmess,
        "trojan" => crate::ir::OutboundType::Trojan,
        "ssh" => crate::ir::OutboundType::Ssh,
        "dns" => crate::ir::OutboundType::Dns,
        "tor" => crate::ir::OutboundType::Tor,
        "anytls" => crate::ir::OutboundType::Anytls,
        "hysteria" => crate::ir::OutboundType::Hysteria,
        "wireguard" => crate::ir::OutboundType::Wireguard,
        "tailscale" => crate::ir::OutboundType::Tailscale,
        _ => crate::ir::OutboundType::Block,
    }
}

/// Lower the `/outbounds` array from raw JSON into `ConfigIR.outbounds`.
///
/// This is the single outbound lowering owner — `to_ir_v1()` delegates here.
pub(super) fn lower_outbounds(doc: &Value, ir: &mut ConfigIR) {
    let Some(outs) = doc.get("outbounds").and_then(|v| v.as_array()) else {
        return;
    };

    for o in outs {
        let mut ob = crate::ir::OutboundIR {
            ty: outbound_type_for(o),
            server: o
                .get("server")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            port: o
                .get("port")
                .or_else(|| o.get("server_port"))
                .and_then(|v| v.as_u64())
                .map(|x| x as u16),
            udp: o.get("udp").and_then(|v| v.as_str()).map(|s| s.to_string()),
            name: o
                .get("tag")
                .or_else(|| o.get("name"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            members: None,
            default_member: None,
            domain_strategy: o
                .get("domain_strategy")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            method: None,
            credentials: o.get("credentials").map(|c| Credentials {
                username: c
                    .get("username")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                password: c
                    .get("password")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                username_env: c
                    .get("username_env")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                password_env: c
                    .get("password_env")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
            }),
            uuid: o
                .get("uuid")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            flow: o
                .get("flow")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            security: o
                .get("security")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            alter_id: o
                .get("alter_id")
                .and_then(|v| v.as_u64())
                .and_then(|x| u8::try_from(x).ok()),
            encryption: o
                .get("encryption")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            network: o
                .get("network")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            packet_encoding: o
                .get("packet_encoding")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            transport: None,
            ws_path: o
                .get("ws_path")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            ws_host: o
                .get("ws_host")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            h2_path: o
                .get("h2_path")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            h2_host: o
                .get("h2_host")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            grpc_service: None,
            grpc_method: None,
            grpc_authority: None,
            grpc_metadata: Vec::new(),
            http_upgrade_path: None,
            http_upgrade_headers: Vec::new(),
            tls_sni: o
                .get("tls_sni")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            tls_alpn: match o.get("tls_alpn") {
                Some(Value::String(s)) => {
                    let v = s
                        .split(',')
                        .map(|x| x.trim().to_string())
                        .filter(|x| !x.is_empty())
                        .collect::<Vec<_>>();
                    if v.is_empty() {
                        None
                    } else {
                        Some(v)
                    }
                }
                Some(Value::Array(arr)) => {
                    let v = arr
                        .iter()
                        .filter_map(|it| it.as_str().map(|s| s.trim().to_string()))
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>();
                    if v.is_empty() {
                        None
                    } else {
                        Some(v)
                    }
                }
                _ => None,
            },
            tls_ca_paths: Vec::new(),
            tls_ca_pem: Vec::new(),
            tls_client_cert_path: None,
            tls_client_key_path: None,
            tls_client_cert_pem: None,
            tls_client_key_pem: None,
            reality_enabled: None,
            reality_public_key: None,
            reality_short_id: None,
            reality_server_name: None,
            password: o
                .get("password")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            version: o.get("version").and_then(|v| v.as_u64()).map(|x| x as u8),
            plugin: o
                .get("plugin")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            plugin_opts: o
                .get("plugin_opts")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            token: o
                .get("token")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            congestion_control: o
                .get("congestion_control")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            alpn: o
                .get("alpn")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            skip_cert_verify: o.get("skip_cert_verify").and_then(|v| v.as_bool()),
            udp_relay_mode: o
                .get("udp_relay_mode")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            udp_over_stream: o.get("udp_over_stream").and_then(|v| v.as_bool()),
            zero_rtt_handshake: o.get("zero_rtt_handshake").and_then(|v| v.as_bool()),
            up_mbps: parse_u32_field(o.get("up_mbps")),
            down_mbps: parse_u32_field(o.get("down_mbps")),
            obfs: o
                .get("obfs")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            salamander: o
                .get("salamander")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            brutal_up_mbps: o
                .get("brutal")
                .and_then(|v| v.as_object())
                .and_then(|b| parse_u32_field(b.get("up_mbps"))),
            brutal_down_mbps: o
                .get("brutal")
                .and_then(|v| v.as_object())
                .and_then(|b| parse_u32_field(b.get("down_mbps"))),
            ssh_private_key: None,
            ssh_private_key_path: None,
            ssh_private_key_passphrase: None,
            ssh_host_key_verification: None,
            ssh_known_hosts_path: None,
            ssh_connection_pool_size: None,
            ssh_compression: None,
            ssh_keepalive_interval: None,
            connect_timeout_sec: None,
            tor_proxy_addr: None,
            tor_executable_path: None,
            tor_extra_args: Vec::new(),
            tor_data_directory: None,
            tor_options: None,
            test_url: None,
            test_interval_ms: None,
            test_timeout_ms: None,
            test_tolerance_ms: None,
            interrupt_exist_connections: None,
            dns_transport: None,
            dns_timeout_ms: None,
            dns_query_timeout_ms: None,
            dns_tls_server_name: None,
            dns_enable_edns0: None,
            dns_edns0_buffer_size: None,
            dns_doh_url: None,
            hysteria_protocol: None,
            hysteria_auth: None,
            hysteria_recv_window_conn: None,
            hysteria_recv_window: None,
            wireguard_system_interface: None,
            wireguard_interface: None,
            wireguard_local_address: Vec::new(),
            wireguard_source_v4: None,
            wireguard_source_v6: None,
            wireguard_allowed_ips: Vec::new(),
            wireguard_private_key: None,
            wireguard_peer_public_key: None,
            wireguard_pre_shared_key: None,
            wireguard_persistent_keepalive: None,
            anytls_padding: extract_string_list(o.get("anytls_padding")),
            bind_interface: o
                .get("bind_interface")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            detour: o
                .get("detour")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            inet4_bind_address: o
                .get("inet4_bind_address")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            inet6_bind_address: o
                .get("inet6_bind_address")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            routing_mark: o
                .get("routing_mark")
                .and_then(|v| v.as_u64())
                .map(|x| x as u32),
            reuse_addr: o.get("reuse_addr").and_then(|v| v.as_bool()),
            connect_timeout: o
                .get("connect_timeout")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            tcp_fast_open: o.get("tcp_fast_open").and_then(|v| v.as_bool()),
            tcp_multi_path: o.get("tcp_multi_path").and_then(|v| v.as_bool()),
            udp_fragment: o.get("udp_fragment").and_then(|v| v.as_bool()),
            mux_max_streams: o
                .get("mux_max_streams")
                .and_then(|v| v.as_u64())
                .map(|x| x as usize),
            mux_window_size: o
                .get("mux_window_size")
                .and_then(|v| v.as_u64())
                .map(|x| x as u32),
            mux_padding: o.get("mux_padding").and_then(|v| v.as_bool()),
            mux_reuse_timeout: o.get("mux_reuse_timeout").and_then(|v| v.as_u64()),
            multiplex: None,
            obfs_param: o
                .get("obfs_param")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            protocol: o
                .get("protocol")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            protocol_param: o
                .get("protocol_param")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            udp_over_tcp: o.get("udp_over_tcp").and_then(|v| v.as_bool()),
            udp_over_tcp_version: o
                .get("udp_over_tcp_version")
                .and_then(|v| v.as_u64())
                .map(|x| x as u8),
            utls_fingerprint: o
                .get("utls_fingerprint")
                .or_else(|| o.get("fingerprint"))
                .or_else(|| o.get("tls_fingerprint"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
        };

        if let Some(transport_val) = o.get("transport") {
            let mut tokens: Vec<String> = Vec::new();
            match transport_val {
                Value::Array(arr) => {
                    for item in arr {
                        match item {
                            Value::String(s) => {
                                for part in s.split(',') {
                                    push_transport_token(&mut tokens, part);
                                }
                            }
                            Value::Object(obj) => {
                                parse_transport_object(obj, &mut ob, &mut tokens);
                            }
                            _ => {}
                        }
                    }
                }
                Value::String(s) => {
                    for part in s.split(',') {
                        push_transport_token(&mut tokens, part);
                    }
                }
                Value::Object(obj) => {
                    parse_transport_object(obj, &mut ob, &mut tokens);
                }
                _ => {}
            }
            if !tokens.is_empty() {
                ob.transport = Some(tokens);
            }
        }

        ob.members = extract_string_list(o.get("members"));
        if ob.members.is_none() {
            ob.members = extract_string_list(o.get("outbounds"));
        }
        ob.default_member = o
            .get("default")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        ob.interrupt_exist_connections = o
            .get("interrupt_exist_connections")
            .and_then(|v| v.as_bool());
        ob.method = o
            .get("method")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        if ob.ty == crate::ir::OutboundType::Shadowsocks && ob.method.is_none() {
            ob.method = Some("aes-256-gcm".to_string());
        }

        if matches!(ob.ty, crate::ir::OutboundType::UrlTest) {
            ob.test_url = Some(
                o.get("url")
                    .and_then(|v| v.as_str())
                    .unwrap_or(DEFAULT_URLTEST_URL)
                    .to_string(),
            );
            ob.test_interval_ms = parse_seconds_field_to_millis(o.get("interval"))
                .or_else(|| o.get("interval_ms").and_then(|v| v.as_u64()))
                .or(Some(DEFAULT_URLTEST_INTERVAL_MS));
            ob.test_timeout_ms = parse_seconds_field_to_millis(o.get("timeout"))
                .or_else(|| o.get("timeout_ms").and_then(|v| v.as_u64()))
                .or(Some(DEFAULT_URLTEST_TIMEOUT_MS));
            ob.test_tolerance_ms = parse_millis_field(o.get("tolerance"))
                .or_else(|| o.get("tolerance_ms").and_then(|v| v.as_u64()))
                .or(Some(DEFAULT_URLTEST_TOLERANCE_MS));
        }

        if matches!(
            ob.ty,
            crate::ir::OutboundType::Selector | crate::ir::OutboundType::UrlTest
        ) && ob.members.is_none()
        {
            ob.members = Some(Vec::new());
        }

        if ob.credentials.is_none() {
            let top_user = o
                .get("username")
                .or_else(|| o.get("user"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let top_pass = o
                .get("password")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            if top_user.is_some() || top_pass.is_some() {
                ob.credentials = Some(Credentials {
                    username: top_user,
                    password: top_pass,
                    username_env: None,
                    password_env: None,
                });
            }
        }

        if matches!(ob.ty, crate::ir::OutboundType::Hysteria) {
            if ob.hysteria_protocol.is_none() {
                ob.hysteria_protocol = o
                    .get("protocol")
                    .or_else(|| o.get("hysteria_protocol"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
            }
            if ob.hysteria_auth.is_none() {
                ob.hysteria_auth = o
                    .get("auth_str")
                    .or_else(|| o.get("hysteria_auth"))
                    .or_else(|| o.get("auth"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
            }
            if ob.hysteria_recv_window_conn.is_none() {
                ob.hysteria_recv_window_conn = o
                    .get("recv_window_conn")
                    .or_else(|| o.get("hysteria_recv_window_conn"))
                    .and_then(|v| v.as_u64());
            }
            if ob.hysteria_recv_window.is_none() {
                ob.hysteria_recv_window = o
                    .get("recv_window")
                    .or_else(|| o.get("hysteria_recv_window"))
                    .and_then(|v| v.as_u64());
            }
        }

        if matches!(ob.ty, crate::ir::OutboundType::Ssh) {
            ob.ssh_private_key = o
                .get("private_key")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            ob.ssh_private_key_path = o
                .get("private_key_path")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            ob.ssh_private_key_passphrase = o
                .get("private_key_passphrase")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            ob.ssh_host_key_verification = o.get("host_key_verification").and_then(|v| v.as_bool());
            ob.ssh_known_hosts_path = o
                .get("known_hosts_path")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            ob.ssh_connection_pool_size = o
                .get("connection_pool_size")
                .and_then(|v| v.as_u64())
                .map(|x| x as usize);
            ob.ssh_compression = o.get("compression").and_then(|v| v.as_bool());
            ob.ssh_keepalive_interval = o.get("keepalive_interval").and_then(|v| v.as_u64());
        }

        if matches!(ob.ty, crate::ir::OutboundType::Wireguard) {
            if ob.wireguard_system_interface.is_none() {
                ob.wireguard_system_interface = o.get("system_interface").and_then(|v| v.as_bool());
            }
            if ob.wireguard_interface.is_none() {
                ob.wireguard_interface = o
                    .get("wireguard_interface")
                    .or_else(|| o.get("interface_name"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
            }
            if ob.wireguard_local_address.is_empty() {
                if let Some(list) = extract_string_list(
                    o.get("wireguard_local_address")
                        .or_else(|| o.get("local_address")),
                ) {
                    ob.wireguard_local_address = list;
                }
            }
            if ob.wireguard_allowed_ips.is_empty() {
                if let Some(list) = extract_string_list(o.get("allowed_ips")) {
                    ob.wireguard_allowed_ips = list;
                }
            }
            if ob.wireguard_private_key.is_none() {
                ob.wireguard_private_key = o
                    .get("private_key")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
            }
            if ob.wireguard_peer_public_key.is_none() {
                ob.wireguard_peer_public_key = o
                    .get("peer_public_key")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
            }
            if ob.wireguard_pre_shared_key.is_none() {
                ob.wireguard_pre_shared_key = o
                    .get("pre_shared_key")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
            }
            if ob.wireguard_source_v4.is_none() {
                ob.wireguard_source_v4 = o
                    .get("wireguard_source_v4")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
            }
            if ob.wireguard_source_v6.is_none() {
                ob.wireguard_source_v6 = o
                    .get("wireguard_source_v6")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
            }
            if ob.wireguard_persistent_keepalive.is_none() {
                ob.wireguard_persistent_keepalive = o
                    .get("persistent_keepalive_interval")
                    .and_then(|v| v.as_u64())
                    .and_then(|x| u16::try_from(x).ok());
            }

            if ob.wireguard_allowed_ips.is_empty() || ob.wireguard_peer_public_key.is_none() {
                if let Some(peers) = o.get("peers").and_then(|v| v.as_array()) {
                    if let Some(peer) = peers.first() {
                        if ob.wireguard_allowed_ips.is_empty() {
                            if let Some(list) = extract_string_list(peer.get("allowed_ips")) {
                                ob.wireguard_allowed_ips = list;
                            }
                        }
                        if ob.wireguard_peer_public_key.is_none() {
                            ob.wireguard_peer_public_key = peer
                                .get("public_key")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());
                        }
                        if ob.wireguard_pre_shared_key.is_none() {
                            ob.wireguard_pre_shared_key = peer
                                .get("pre_shared_key")
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());
                        }
                        if ob.wireguard_persistent_keepalive.is_none() {
                            ob.wireguard_persistent_keepalive = peer
                                .get("persistent_keepalive_interval")
                                .and_then(|v| v.as_u64())
                                .and_then(|x| u16::try_from(x).ok());
                        }
                    }
                }
            }
        }

        ob.connect_timeout_sec = o
            .get("connect_timeout")
            .and_then(|v| v.as_u64())
            .map(|x| x as u32);

        if let Some(ws) = o.get("ws").and_then(|v| v.as_object()) {
            if ob.ws_path.is_none() {
                ob.ws_path = ws
                    .get("path")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
            }
            if ob.ws_host.is_none() {
                ob.ws_host = ws
                    .get("host")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
            }
        }
        if let Some(h2) = o.get("h2").and_then(|v| v.as_object()) {
            if ob.h2_path.is_none() {
                ob.h2_path = h2
                    .get("path")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
            }
            if ob.h2_host.is_none() {
                ob.h2_host = h2
                    .get("host")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
            }
        }
        if let Some(tls) = o.get("tls").and_then(|v| v.as_object()) {
            if ob.tls_sni.is_none() {
                ob.tls_sni = tls
                    .get("sni")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
            }
            if ob.tls_alpn.is_none() {
                if let Some(val) = tls.get("alpn") {
                    ob.tls_alpn = match val {
                        Value::String(s) => {
                            let v = s
                                .split(',')
                                .map(|x| x.trim().to_string())
                                .filter(|x| !x.is_empty())
                                .collect::<Vec<_>>();
                            if v.is_empty() {
                                None
                            } else {
                                Some(v)
                            }
                        }
                        Value::Array(arr) => {
                            let v = arr
                                .iter()
                                .filter_map(|it| it.as_str().map(|s| s.trim().to_string()))
                                .filter(|s| !s.is_empty())
                                .collect::<Vec<_>>();
                            if v.is_empty() {
                                None
                            } else {
                                Some(v)
                            }
                        }
                        _ => None,
                    };
                }
            }
            if ob.alpn.is_none() {
                ob.alpn = tls
                    .get("alpn")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
            }
            if ob.skip_cert_verify.is_none() {
                ob.skip_cert_verify = tls
                    .get("skip_cert_verify")
                    .and_then(|v| v.as_bool())
                    .or_else(|| tls.get("allow_insecure").and_then(|v| v.as_bool()));
            }

            if ob.tls_ca_paths.is_empty() {
                if let Some(arr) = tls.get("ca_paths").and_then(|v| v.as_array()) {
                    for p in arr {
                        if let Some(s) = p.as_str() {
                            let s = s.trim();
                            if !s.is_empty() {
                                ob.tls_ca_paths.push(s.to_string());
                            }
                        }
                    }
                }
            }
            if ob.tls_ca_pem.is_empty() {
                match tls.get("ca_pem") {
                    Some(v) if v.is_array() => {
                        if let Some(items) = v.as_array() {
                            for it in items {
                                if let Some(s) = it.as_str() {
                                    let s = s.trim();
                                    if !s.is_empty() {
                                        ob.tls_ca_pem.push(s.to_string());
                                    }
                                }
                            }
                        }
                    }
                    Some(v) if v.is_string() => {
                        if let Some(s) = v.as_str() {
                            let s = s.trim();
                            if !s.is_empty() {
                                ob.tls_ca_pem.push(s.to_string());
                            }
                        }
                    }
                    _ => {}
                }
            }
            if ob.tls_client_cert_path.is_none() {
                ob.tls_client_cert_path = tls
                    .get("client_cert_path")
                    .or_else(|| tls.get("client_cert"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
            }
            if ob.tls_client_key_path.is_none() {
                ob.tls_client_key_path = tls
                    .get("client_key_path")
                    .or_else(|| tls.get("client_key"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
            }
            if ob.tls_client_cert_pem.is_none() {
                ob.tls_client_cert_pem = tls
                    .get("client_cert_pem")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
            }
            if ob.tls_client_key_pem.is_none() {
                ob.tls_client_key_pem = tls
                    .get("client_key_pem")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
            }

            if let Some(reality) = tls.get("reality").and_then(|v| v.as_object()) {
                ob.reality_enabled = reality.get("enabled").and_then(|v| v.as_bool());
                ob.reality_public_key = reality
                    .get("public_key")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                ob.reality_short_id = reality
                    .get("short_id")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                ob.reality_server_name = reality
                    .get("server_name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
            }
        }

        ir.outbounds.push(ob);
    }
}

/// Validate `/outbounds` array structure, types, tags, and unknown fields.
///
/// 校验 `/outbounds` 数组结构、类型、标签及未知字段。
pub(crate) fn validate_outbounds(doc: &Value, allow_unknown: bool, issues: &mut Vec<Value>) {
    // /outbounds must be array (if present)
    if let Some(outbounds_val) = doc.get("outbounds") {
        if !outbounds_val.is_array() {
            issues.push(emit_issue(
                "error",
                IssueCode::TypeMismatch,
                "/outbounds",
                "outbounds must be an array",
                "use []",
            ));
        }
    }
    if let Some(arr) = doc.get("outbounds").and_then(|v| v.as_array()) {
        for (i, ob) in arr.iter().enumerate() {
            // Each outbound must be an object
            if !ob.is_object() {
                issues.push(emit_issue(
                    "error",
                    IssueCode::TypeMismatch,
                    &format!("/outbounds/{}", i),
                    "outbound item must be an object",
                    "use {}",
                ));
                continue;
            }

            // type is required
            if ob.get("type").is_none() {
                issues.push(emit_issue(
                    "error",
                    IssueCode::MissingRequired,
                    &format!("/outbounds/{}/type", i),
                    "missing required field",
                    "add it",
                ));
            } else if let Some(ty) = ob.get("type") {
                if !ty.is_string() {
                    issues.push(emit_issue(
                        "error",
                        IssueCode::TypeMismatch,
                        &format!("/outbounds/{}/type", i),
                        "type must be a string",
                        "use string value",
                    ));
                }
            }

            // tag/name should be string if present
            if let Some(tag_val) = ob.get("tag") {
                if !tag_val.is_string() {
                    issues.push(emit_issue(
                        "error",
                        IssueCode::TypeMismatch,
                        &format!("/outbounds/{}/tag", i),
                        "tag must be a string",
                        "use string value",
                    ));
                }
            }

            // additionalProperties=false (V2 allowed fields)
            if let Some(map) = ob.as_object() {
                let allowed = allowed_outbound_keys();
                for k in map.keys() {
                    if !allowed.contains(k) {
                        let kind = if allow_unknown { "warning" } else { "error" };
                        issues.push(emit_issue(
                            kind,
                            IssueCode::UnknownField,
                            &format!("/outbounds/{}/{}", i, k),
                            "unknown field",
                            "remove it",
                        ));
                    }
                }
            }
        }
    }
}

/// Check outbound TLS configurations for capabilities that have known
/// limitations in the Rust implementation. Emits info-level diagnostics for:
/// - uTLS fingerprints other than "chrome" or empty (limited support)
/// - ECH (encrypted_client_hello) configuration (behind feature flag)
/// - REALITY TLS (supported, informational notice)
///
/// 检查出站 TLS 配置中在 Rust 实现中有已知限制的功能。
/// 为以下情况发出 info 级别的诊断：
/// - 非 "chrome" 或空的 uTLS 指纹（有限支持）
/// - ECH（encrypted_client_hello）配置（需要 feature flag）
/// - REALITY TLS（已支持，信息通知）
pub fn check_tls_capabilities(doc: &Value) -> Vec<Value> {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum QuicEchMode {
        Reject,
        Experimental,
    }

    fn ech_enabled(ech_val: &Value) -> bool {
        match ech_val {
            Value::Bool(b) => *b,
            Value::Object(o) => o.get("enabled").and_then(|v| v.as_bool()).unwrap_or(true),
            _ => false,
        }
    }

    fn has_quic_token(value: Option<&Value>) -> bool {
        match value {
            Some(Value::String(s)) => s
                .split(',')
                .map(str::trim)
                .any(|token| token.eq_ignore_ascii_case("quic")),
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(Value::as_str)
                .any(|token| token.eq_ignore_ascii_case("quic")),
            Some(Value::Object(map)) => map
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|ty| ty.eq_ignore_ascii_case("quic")),
            _ => false,
        }
    }

    fn outbound_uses_quic(obj: &serde_json::Map<String, Value>) -> bool {
        if obj.get("type").and_then(Value::as_str).is_some_and(|ty| {
            ty.eq_ignore_ascii_case("tuic")
                || ty.eq_ignore_ascii_case("hysteria")
                || ty.eq_ignore_ascii_case("hysteria2")
        }) {
            return true;
        }
        if has_quic_token(obj.get("network")) || has_quic_token(obj.get("transport")) {
            return true;
        }
        obj.get("udp_relay_mode")
            .and_then(Value::as_str)
            .is_some_and(|mode| mode.eq_ignore_ascii_case("quic"))
    }

    fn read_quic_ech_mode(doc: &Value, issues: &mut Vec<Value>) -> QuicEchMode {
        let Some(exp) = doc.get("experimental") else {
            return QuicEchMode::Reject;
        };
        let Some(raw) = exp.get("quic_ech_mode") else {
            return QuicEchMode::Reject;
        };

        let Some(mode) = raw.as_str() else {
            issues.push(emit_issue(
                "error",
                IssueCode::TypeMismatch,
                "/experimental/quic_ech_mode",
                "experimental.quic_ech_mode must be a string: 'reject' or 'experimental'",
                "set experimental.quic_ech_mode to 'reject' (default) or 'experimental'",
            ));
            return QuicEchMode::Reject;
        };

        match mode.trim().to_ascii_lowercase().as_str() {
            "" | "reject" => QuicEchMode::Reject,
            "experimental" => QuicEchMode::Experimental,
            _ => {
                issues.push(emit_issue(
                    "error",
                    IssueCode::InvalidEnum,
                    "/experimental/quic_ech_mode",
                    "experimental.quic_ech_mode must be 'reject' or 'experimental'",
                    "use 'reject' for production safety; use 'experimental' only for controlled tests",
                ));
                QuicEchMode::Reject
            }
        }
    }

    let mut issues = Vec::new();
    let quic_ech_mode = read_quic_ech_mode(doc, &mut issues);

    let outbounds = match doc.get("outbounds").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => return issues,
    };

    for (i, ob) in outbounds.iter().enumerate() {
        let obj = match ob.as_object() {
            Some(o) => o,
            None => continue,
        };

        let outbound_tag = obj
            .get("tag")
            .or_else(|| obj.get("name"))
            .and_then(|v| v.as_str())
            .unwrap_or("unnamed");

        // Check uTLS fingerprint
        if let Some(fp_val) = obj.get("utls_fingerprint").or_else(|| {
            // Also check nested tls.utls.fingerprint pattern
            obj.get("tls")
                .and_then(|t| t.get("utls"))
                .and_then(|u| u.get("fingerprint"))
        }) {
            if let Some(fp) = fp_val.as_str() {
                let fp_lower = fp.to_ascii_lowercase();
                if !fp_lower.is_empty() && fp_lower != "chrome" {
                    issues.push(emit_issue(
                        "info",
                        IssueCode::Deprecated,
                        &format!("/outbounds/{}/utls_fingerprint", i),
                        &format!(
                            "outbound '{}': uTLS fingerprint '{}' has limited support in Rust; \
                             'chrome' is the most reliable fingerprint, others may fall back to native TLS",
                            outbound_tag, fp
                        ),
                        "use 'chrome' fingerprint for best compatibility, or omit for native TLS",
                    ));
                }
            }
        }

        // Check ECH (encrypted_client_hello)
        let ech_loc = if let Some(v) = obj.get("encrypted_client_hello") {
            Some(("encrypted_client_hello", v))
        } else if let Some(v) = obj.get("tls").and_then(|t| t.get("ech")) {
            Some(("tls/ech", v))
        } else {
            obj.get("tls")
                .and_then(|t| t.get("encrypted_client_hello"))
                .map(|v| ("tls/encrypted_client_hello", v))
        };

        if let Some((ech_ptr_suffix, ech_val)) = ech_loc {
            let ech_enabled = ech_enabled(ech_val);
            if ech_enabled {
                issues.push(emit_issue(
                    "info",
                    IssueCode::Deprecated,
                    &format!("/outbounds/{}/encrypted_client_hello", i),
                    &format!(
                        "outbound '{}': Encrypted Client Hello (ECH) is behind the 'tls_ech' feature flag; \
                         without it, ECH configuration is silently ignored",
                        outbound_tag
                    ),
                    "enable the 'tls_ech' feature flag at build time for ECH support",
                ));

                if outbound_uses_quic(obj) {
                    match quic_ech_mode {
                        QuicEchMode::Reject => {
                            issues.push(emit_issue(
                                "error",
                                IssueCode::Conflict,
                                &format!("/outbounds/{}/{}", i, ech_ptr_suffix),
                                &format!(
                                    "outbound '{}': QUIC + ECH is not supported in the current Rust implementation; \
                                     configuration is rejected by default to avoid silent fallback",
                                    outbound_tag
                                ),
                                "set experimental.quic_ech_mode='experimental' only for controlled interop tests, \
                                 or use TCP-based TLS ECH outbounds",
                            ));
                        }
                        QuicEchMode::Experimental => {
                            issues.push(emit_issue(
                                "warning",
                                IssueCode::Conflict,
                                &format!("/outbounds/{}/{}", i, ech_ptr_suffix),
                                &format!(
                                    "outbound '{}': QUIC + ECH is in experimental mode; runtime behavior may fail or change and should not be treated as production-ready",
                                    outbound_tag
                                ),
                                "keep experimental scope small, capture handshake evidence, and prefer TCP+TLS ECH for production paths",
                            ));
                        }
                    }
                }
            }
        }

        // Check REALITY TLS
        let reality_enabled = obj
            .get("reality_enabled")
            .or_else(|| {
                obj.get("tls")
                    .and_then(|t| t.get("reality"))
                    .and_then(|r| r.get("enabled"))
            })
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if reality_enabled {
            issues.push(emit_issue(
                "info",
                IssueCode::Deprecated,
                &format!("/outbounds/{}/reality_enabled", i),
                &format!(
                    "outbound '{}': REALITY TLS is supported in Rust via rustls; \
                     verify public_key and short_id are correctly configured",
                    outbound_tag
                ),
                "ensure reality_public_key and reality_short_id are set correctly",
            ));
        }
    }

    issues
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::ConfigIR;
    use crate::validator::v2::{to_ir_v1, validate_v2};
    use serde_json::json;

    #[test]
    fn test_validate_outbounds_not_array() {
        let doc = serde_json::json!({
            "outbounds": "not-an-array"
        });
        let mut issues = Vec::new();
        validate_outbounds(&doc, false, &mut issues);
        assert!(
            issues.iter().any(|i| {
                i["kind"] == "error"
                    && i["code"] == "TypeMismatch"
                    && i["ptr"] == "/outbounds"
                    && i["msg"]
                        .as_str()
                        .is_some_and(|m| m.contains("must be an array"))
            }),
            "should report outbounds must be array: {:?}",
            issues
        );
    }

    #[test]
    fn test_validate_outbounds_item_not_object() {
        let doc = serde_json::json!({
            "outbounds": ["not-an-object"]
        });
        let mut issues = Vec::new();
        validate_outbounds(&doc, false, &mut issues);
        assert!(
            issues.iter().any(|i| {
                i["kind"] == "error"
                    && i["code"] == "TypeMismatch"
                    && i["ptr"] == "/outbounds/0"
                    && i["msg"]
                        .as_str()
                        .is_some_and(|m| m.contains("outbound item must be an object"))
            }),
            "should report item must be object: {:?}",
            issues
        );
    }

    #[test]
    fn test_validate_outbounds_missing_type() {
        let doc = serde_json::json!({
            "outbounds": [{"name": "no-type"}]
        });
        let mut issues = Vec::new();
        validate_outbounds(&doc, false, &mut issues);
        assert!(
            issues.iter().any(|i| {
                i["kind"] == "error"
                    && i["code"] == "MissingRequired"
                    && i["ptr"] == "/outbounds/0/type"
            }),
            "should report missing type: {:?}",
            issues
        );
    }

    #[test]
    fn test_validate_outbounds_type_not_string() {
        let doc = serde_json::json!({
            "outbounds": [{"type": 42}]
        });
        let mut issues = Vec::new();
        validate_outbounds(&doc, false, &mut issues);
        assert!(
            issues.iter().any(|i| {
                i["kind"] == "error"
                    && i["code"] == "TypeMismatch"
                    && i["ptr"] == "/outbounds/0/type"
                    && i["msg"]
                        .as_str()
                        .is_some_and(|m| m.contains("type must be a string"))
            }),
            "should report type must be string: {:?}",
            issues
        );
    }

    #[test]
    fn test_validate_outbounds_tag_not_string() {
        let doc = serde_json::json!({
            "outbounds": [{"type": "direct", "tag": 123}]
        });
        let mut issues = Vec::new();
        validate_outbounds(&doc, false, &mut issues);
        assert!(
            issues.iter().any(|i| {
                i["kind"] == "error"
                    && i["code"] == "TypeMismatch"
                    && i["ptr"] == "/outbounds/0/tag"
                    && i["msg"]
                        .as_str()
                        .is_some_and(|m| m.contains("tag must be a string"))
            }),
            "should report tag must be string: {:?}",
            issues
        );
    }

    #[test]
    fn test_validate_outbounds_unknown_field_strict() {
        let doc = serde_json::json!({
            "outbounds": [
                {"type": "direct", "name": "d", "unknown_outbound_field": "test"}
            ]
        });
        let mut issues = Vec::new();
        validate_outbounds(&doc, false, &mut issues);
        assert!(
            issues.iter().any(|i| {
                i["kind"] == "error"
                    && i["code"] == "UnknownField"
                    && i["ptr"] == "/outbounds/0/unknown_outbound_field"
            }),
            "should report unknown field as error in strict mode: {:?}",
            issues
        );
    }

    #[test]
    fn test_validate_outbounds_unknown_field_allow_unknown() {
        let doc = serde_json::json!({
            "outbounds": [
                {"type": "direct", "name": "d", "unknown_outbound_field": "test"}
            ]
        });
        let mut issues = Vec::new();
        validate_outbounds(&doc, true, &mut issues);
        assert!(
            issues.iter().any(|i| {
                i["kind"] == "warning"
                    && i["code"] == "UnknownField"
                    && i["ptr"] == "/outbounds/0/unknown_outbound_field"
            }),
            "should report unknown field as warning in allow_unknown mode: {:?}",
            issues
        );
        // No errors
        assert!(
            !issues.iter().any(|i| i["kind"] == "error"),
            "should have no errors in allow_unknown mode: {:?}",
            issues
        );
    }

    #[test]
    fn test_validate_outbounds_valid_direct() {
        let doc = serde_json::json!({
            "outbounds": [{"type": "direct", "name": "direct-out"}]
        });
        let mut issues = Vec::new();
        validate_outbounds(&doc, false, &mut issues);
        assert!(
            issues.is_empty(),
            "valid direct outbound should produce no issues: {:?}",
            issues
        );
    }

    #[test]
    fn test_validate_outbounds_absent() {
        let doc = serde_json::json!({});
        let mut issues = Vec::new();
        validate_outbounds(&doc, false, &mut issues);
        assert!(
            issues.is_empty(),
            "absent outbounds should produce no issues: {:?}",
            issues
        );
    }

    #[test]
    fn test_tls_no_outbounds_no_crash() {
        let doc = serde_json::json!({
            "schema_version": 2
        });
        let issues = check_tls_capabilities(&doc);
        assert!(
            issues.is_empty(),
            "No outbounds should produce no TLS capability issues"
        );
    }

    #[test]
    fn test_tls_utls_non_chrome_fingerprint() {
        let doc = serde_json::json!({
            "outbounds": [{
                "type": "vless",
                "name": "test",
                "utls_fingerprint": "firefox"
            }]
        });
        let issues = check_tls_capabilities(&doc);
        assert!(
            issues.iter().any(|i| {
                i["code"] == "Deprecated"
                    && i["ptr"] == "/outbounds/0/utls_fingerprint"
                    && i["kind"] == "info"
            }),
            "should warn about non-chrome utls: {:?}",
            issues
        );
    }

    #[test]
    fn test_tls_reality_enabled() {
        let doc = serde_json::json!({
            "outbounds": [{
                "type": "vless",
                "name": "test",
                "reality_enabled": true
            }]
        });
        let issues = check_tls_capabilities(&doc);
        assert!(
            issues.iter().any(|i| {
                i["code"] == "Deprecated"
                    && i["ptr"] == "/outbounds/0/reality_enabled"
                    && i["kind"] == "info"
            }),
            "should report reality info: {:?}",
            issues
        );
    }

    #[test]
    fn test_tls_ech_quic_reject() {
        let doc = serde_json::json!({
            "outbounds": [{
                "type": "tuic",
                "name": "test",
                "tls": { "ech": { "enabled": true } }
            }]
        });
        let issues = check_tls_capabilities(&doc);
        assert!(
            issues
                .iter()
                .any(|i| { i["kind"] == "error" && i["code"] == "Conflict" }),
            "should block QUIC+ECH by default: {:?}",
            issues
        );
    }

    #[test]
    fn test_parse_reality_config() {
        let json = json!({
            "schema_version": 2,
            "outbounds": [{
                "type": "vless",
                "name": "reality-out",
                "server": "example.com",
                "port": 443,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "tls": {
                    "enabled": true,
                    "sni": "www.apple.com",
                    "reality": {
                        "enabled": true,
                        "public_key": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                        "short_id": "01ab",
                        "server_name": "www.apple.com"
                    }
                }
            }]
        });

        let ir = to_ir_v1(&json);
        assert_eq!(ir.outbounds.len(), 1);
        let outbound = &ir.outbounds[0];
        assert_eq!(outbound.name, Some("reality-out".to_string()));
        assert_eq!(outbound.reality_enabled, Some(true));
        assert_eq!(
            outbound.reality_public_key,
            Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string())
        );
        assert_eq!(outbound.reality_short_id, Some("01ab".to_string()));
        assert_eq!(
            outbound.reality_server_name,
            Some("www.apple.com".to_string())
        );
        assert!(outbound.validate_reality().is_ok());
    }

    #[test]
    fn test_parse_tuic_outbound_fields() {
        let json = json!({
            "schema_version": 2,
            "outbounds": [{
                "type": "tuic",
                "name": "tuic-out",
                "server": "tuic.example.com",
                "port": 443,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "token": "secret-token",
                "password": "optional-pass",
                "congestion_control": "bbr",
                "udp_relay_mode": "quic",
                "udp_over_stream": true,
                "skip_cert_verify": true,
                "tls": {
                    "alpn": "h3",
                    "skip_cert_verify": true
                }
            }]
        });

        let ir = to_ir_v1(&json);
        assert_eq!(ir.outbounds.len(), 1);
        let outbound = &ir.outbounds[0];
        assert_eq!(outbound.ty, crate::ir::OutboundType::Tuic);
        assert_eq!(outbound.name.as_deref(), Some("tuic-out"));
        assert_eq!(outbound.token.as_deref(), Some("secret-token"));
        assert_eq!(outbound.password.as_deref(), Some("optional-pass"));
        assert_eq!(outbound.congestion_control.as_deref(), Some("bbr"));
        assert_eq!(outbound.udp_relay_mode.as_deref(), Some("quic"));
        assert_eq!(outbound.udp_over_stream, Some(true));
        assert_eq!(outbound.skip_cert_verify, Some(true));
        assert_eq!(outbound.alpn.as_deref(), Some("h3"));
        assert_eq!(outbound.tls_alpn, Some(vec!["h3".to_string()]));
    }

    #[test]
    fn test_parse_hysteria2_bandwidth_fields() {
        let json = json!({
            "schema_version": 2,
            "outbounds": [{
                "type": "hysteria2",
                "name": "hy2",
                "server": "hy2.example.com",
                "port": 443,
                "password": "secret",
                "up_mbps": 150,
                "down_mbps": "200Mbps",
                "obfs": "obfs-key",
                "salamander": "fingerprint",
                "brutal": {
                    "up_mbps": "300",
                    "down_mbps": "400Mbps"
                }
            }]
        });

        let ir = to_ir_v1(&json);
        assert_eq!(ir.outbounds.len(), 1);
        let outbound = &ir.outbounds[0];
        assert_eq!(outbound.ty, crate::ir::OutboundType::Hysteria2);
        assert_eq!(outbound.up_mbps, Some(150));
        assert_eq!(outbound.down_mbps, Some(200));
        assert_eq!(outbound.obfs.as_deref(), Some("obfs-key"));
        assert_eq!(outbound.salamander.as_deref(), Some("fingerprint"));
        assert_eq!(outbound.brutal_up_mbps, Some(300));
        assert_eq!(outbound.brutal_down_mbps, Some(400));
    }

    #[test]
    fn test_parse_hysteria_auth_str_alias() {
        let json = json!({
            "schema_version": 2,
            "outbounds": [{
                "type": "hysteria",
                "name": "hy1",
                "server": "hy1.example.com",
                "port": 443,
                "auth_str": "secret-auth"
            }]
        });

        let ir = to_ir_v1(&json);
        assert_eq!(ir.outbounds.len(), 1);
        let outbound = &ir.outbounds[0];
        assert_eq!(outbound.ty, crate::ir::OutboundType::Hysteria);
        assert_eq!(outbound.hysteria_auth.as_deref(), Some("secret-auth"));
    }

    #[test]
    fn test_parse_ssh_user_alias() {
        let json = json!({
            "schema_version": 2,
            "outbounds": [{
                "type": "ssh",
                "name": "ssh-out",
                "server": "ssh.example.com",
                "port": 22,
                "user": "alice",
                "password": "secret"
            }]
        });

        let ir = to_ir_v1(&json);
        assert_eq!(ir.outbounds.len(), 1);
        let outbound = &ir.outbounds[0];
        let creds = outbound.credentials.as_ref().expect("credentials");
        assert_eq!(creds.username.as_deref(), Some("alice"));
        assert_eq!(creds.password.as_deref(), Some("secret"));
    }

    #[test]
    fn test_default_shadowsocks_method() {
        let json = json!({
            "schema_version": 2,
            "outbounds": [{
                "type": "shadowsocks",
                "name": "ss-out",
                "server": "127.0.0.1",
                "port": 8388,
                "password": "secret"
            }]
        });

        let ir = to_ir_v1(&json);
        assert_eq!(ir.outbounds.len(), 1);
        let outbound = &ir.outbounds[0];
        assert_eq!(outbound.ty, crate::ir::OutboundType::Shadowsocks);
        assert_eq!(outbound.method.as_deref(), Some("aes-256-gcm"));
    }

    #[test]
    fn test_parse_transport_object_ws() {
        let json = json!({
            "schema_version": 2,
            "outbounds": [{
                "type": "vless",
                "name": "ws-out",
                "server": "example.com",
                "port": 443,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "transport": {
                    "type": "ws",
                    "path": "/ws",
                    "headers": {
                        "Host": "example.com"
                    }
                }
            }]
        });

        let ir = to_ir_v1(&json);
        assert_eq!(ir.outbounds.len(), 1);
        let outbound = &ir.outbounds[0];
        assert_eq!(outbound.transport.as_ref(), Some(&vec!["ws".to_string()]));
        assert_eq!(outbound.ws_path.as_deref(), Some("/ws"));
        assert_eq!(outbound.ws_host.as_deref(), Some("example.com"));
    }

    #[test]
    fn test_parse_transport_object_grpc() {
        let json = json!({
            "schema_version": 2,
            "outbounds": [{
                "type": "vmess",
                "name": "grpc-out",
                "server": "grpc.example.com",
                "port": 443,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "transport": {
                    "type": "grpc",
                    "service_name": "TunnelService",
                    "method_name": "Tunnel",
                    "authority": "grpc.example.com",
                    "metadata": {
                        "auth": "token",
                        "foo": "bar"
                    }
                }
            }]
        });

        let ir = to_ir_v1(&json);
        assert_eq!(ir.outbounds.len(), 1);
        let outbound = &ir.outbounds[0];
        assert_eq!(outbound.transport.as_ref(), Some(&vec!["grpc".to_string()]));
        assert_eq!(outbound.grpc_service.as_deref(), Some("TunnelService"));
        assert_eq!(outbound.grpc_method.as_deref(), Some("Tunnel"));
        assert_eq!(outbound.grpc_authority.as_deref(), Some("grpc.example.com"));
        let mut metadata: Vec<(String, String)> = outbound
            .grpc_metadata
            .iter()
            .map(|h| (h.key.clone(), h.value.clone()))
            .collect();
        metadata.sort();
        assert_eq!(metadata.len(), 2);
        assert!(metadata.contains(&("auth".to_string(), "token".to_string())));
        assert!(metadata.contains(&("foo".to_string(), "bar".to_string())));
    }

    #[test]
    fn test_parse_transport_object_http_upgrade() {
        let json = json!({
            "schema_version": 2,
            "outbounds": [{
                "type": "vless",
                "name": "hup-out",
                "server": "upgrade.example.com",
                "port": 80,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "transport": {
                    "type": "httpupgrade",
                    "path": "/upgrade",
                    "headers": {
                        "User-Agent": "singbox",
                        "Authorization": "Bearer token"
                    }
                }
            }]
        });

        let ir = to_ir_v1(&json);
        assert_eq!(ir.outbounds.len(), 1);
        let outbound = &ir.outbounds[0];
        assert_eq!(
            outbound.transport.as_ref(),
            Some(&vec!["httpupgrade".to_string()])
        );
        assert_eq!(outbound.http_upgrade_path.as_deref(), Some("/upgrade"));
        let mut headers: Vec<(String, String)> = outbound
            .http_upgrade_headers
            .iter()
            .map(|h| (h.key.clone(), h.value.clone()))
            .collect();
        headers.sort();
        assert_eq!(headers.len(), 2);
        assert!(headers.contains(&("User-Agent".to_string(), "singbox".to_string())));
        assert!(headers.contains(&("Authorization".to_string(), "Bearer token".to_string())));
    }

    #[test]
    fn test_parse_reality_config_nested_tls() {
        let json = json!({
            "schema_version": 2,
            "outbounds": [{
                "type": "vless",
                "name": "reality-out",
                "server": "example.com",
                "port": 443,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "tls": {
                    "sni": "www.apple.com",
                    "alpn": "h2,http/1.1",
                    "reality": {
                        "enabled": true,
                        "public_key": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                        "short_id": "cdef",
                        "server_name": "www.cloudflare.com"
                    }
                }
            }]
        });

        let ir = to_ir_v1(&json);
        assert_eq!(ir.outbounds.len(), 1);
        let outbound = &ir.outbounds[0];
        assert_eq!(outbound.tls_sni, Some("www.apple.com".to_string()));
        assert_eq!(
            outbound.tls_alpn,
            Some(vec!["h2".to_string(), "http/1.1".to_string()])
        );
        assert_eq!(outbound.reality_enabled, Some(true));
        assert_eq!(
            outbound.reality_public_key,
            Some("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string())
        );
        assert_eq!(outbound.reality_short_id, Some("cdef".to_string()));
        assert_eq!(
            outbound.reality_server_name,
            Some("www.cloudflare.com".to_string())
        );
    }

    #[test]
    fn test_parse_reality_config_disabled() {
        let json = json!({
            "schema_version": 2,
            "outbounds": [{
                "type": "vless",
                "name": "normal-vless",
                "server": "example.com",
                "port": 443,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "tls": {
                    "enabled": true,
                    "sni": "example.com",
                    "reality": {
                        "enabled": false
                    }
                }
            }]
        });

        let ir = to_ir_v1(&json);
        assert_eq!(ir.outbounds.len(), 1);
        let outbound = &ir.outbounds[0];
        assert_eq!(outbound.reality_enabled, Some(false));
        assert!(outbound.validate_reality().is_ok());
    }

    #[test]
    fn test_parse_reality_config_without_reality() {
        let json = json!({
            "schema_version": 2,
            "outbounds": [{
                "type": "vless",
                "name": "normal-vless",
                "server": "example.com",
                "port": 443,
                "uuid": "12345678-1234-1234-1234-123456789abc",
                "tls": {
                    "enabled": true,
                    "sni": "example.com"
                }
            }]
        });

        let ir = to_ir_v1(&json);
        assert_eq!(ir.outbounds.len(), 1);
        let outbound = &ir.outbounds[0];
        assert_eq!(outbound.reality_enabled, None);
        assert_eq!(outbound.reality_public_key, None);
        assert_eq!(outbound.reality_short_id, None);
        assert_eq!(outbound.reality_server_name, None);
        assert!(outbound.validate_reality().is_ok());
    }

    #[test]
    fn test_selector_and_urltest_parsing() -> anyhow::Result<()> {
        let json = json!({
            "schema_version": 2,
            "outbounds": [
                { "type": "direct", "name": "direct-1" },
                { "type": "direct", "name": "direct-2" },
                {
                    "type": "selector",
                    "name": "manual",
                    "outbounds": ["direct-1", "direct-2"],
                    "default": "direct-1"
                },
                {
                    "type": "urltest",
                    "name": "auto",
                    "outbounds": ["direct-1"],
                    "interval": "5s",
                    "timeout": 2,
                    "tolerance": "75ms"
                }
            ]
        });

        let ir = to_ir_v1(&json);
        assert_eq!(ir.outbounds.len(), 4);

        let manual = ir
            .outbounds
            .iter()
            .find(|o| o.name.as_deref() == Some("manual"))
            .expect("manual selector");
        assert_eq!(manual.ty, crate::ir::OutboundType::Selector);
        assert_eq!(
            manual.members.as_ref(),
            Some(&vec!["direct-1".to_string(), "direct-2".to_string()])
        );
        assert_eq!(manual.default_member.as_deref(), Some("direct-1"));

        let auto = ir
            .outbounds
            .iter()
            .find(|o| o.name.as_deref() == Some("auto"))
            .expect("urltest selector");
        assert_eq!(auto.ty, crate::ir::OutboundType::UrlTest);
        assert_eq!(auto.members.as_ref(), Some(&vec!["direct-1".to_string()]));
        assert_eq!(auto.test_interval_ms, Some(5_000));
        assert_eq!(auto.test_timeout_ms, Some(2_000));
        assert_eq!(auto.test_tolerance_ms, Some(75));
        assert_eq!(auto.test_url.as_deref(), Some(DEFAULT_URLTEST_URL));
        Ok(())
    }

    #[test]
    fn test_validate_urltest_alias_fields() {
        let json = json!({
            "schema_version": 2,
            "outbounds": [
                {
                    "type": "selector",
                    "name": "manual",
                    "outbounds": ["direct-1", "direct-2"],
                    "default": "direct-1"
                },
                {
                    "type": "urltest",
                    "name": "auto",
                    "outbounds": ["direct-1"],
                    "url": "https://www.gstatic.com/generate_204",
                    "interval": "5m",
                    "timeout": "2s",
                    "tolerance": "75ms"
                }
            ]
        });

        let issues = validate_v2(&json, false);
        assert!(
            issues.is_empty(),
            "unexpected validation issues: {issues:?}"
        );
    }

    #[test]
    fn test_shadowsocks_parsing() {
        let json = json!({
            "schema_version": 2,
            "outbounds": [{
                "type": "shadowsocks",
                "name": "ss-out",
                "server": "1.2.3.4",
                "port": 8388,
                "password": "secret",
                "method": "aes-256-gcm"
            }]
        });

        let ir = to_ir_v1(&json);
        assert_eq!(ir.outbounds.len(), 1);
        let ss = &ir.outbounds[0];
        assert_eq!(ss.ty, crate::ir::OutboundType::Shadowsocks);
        assert_eq!(ss.server.as_deref(), Some("1.2.3.4"));
        assert_eq!(ss.port, Some(8388));
        assert_eq!(ss.password.as_deref(), Some("secret"));
        assert_eq!(ss.method.as_deref(), Some("aes-256-gcm"));
    }

    #[test]
    fn test_parse_outbound_tls_nested_fields() {
        let json = json!({
            "schema_version": 2,
            "outbounds": [{
                "type": "vmess",
                "name": "vmess-internal",
                "server": "vmess.internal",
                "port": 443,
                "tls": {
                    "sni": "internal.example",
                    "alpn": "h2,http/1.1",
                    "skip_cert_verify": true,
                    "ca_paths": ["/etc/ssl/certs/internal-root.pem"],
                    "ca_pem": "-----BEGIN CERTIFICATE-----\nMIIB...snip...\n-----END CERTIFICATE-----",
                    "client_cert_path": "/path/to/client.crt",
                    "client_key_path": "/path/to/client.key"
                }
            }]
        });
        let ir = to_ir_v1(&json);
        assert_eq!(ir.outbounds.len(), 1);
        let ob = &ir.outbounds[0];
        assert_eq!(ob.tls_sni.as_deref(), Some("internal.example"));
        assert_eq!(
            ob.tls_alpn,
            Some(vec!["h2".to_string(), "http/1.1".to_string()])
        );
        assert_eq!(ob.skip_cert_verify, Some(true));
        assert_eq!(
            ob.tls_ca_paths,
            vec!["/etc/ssl/certs/internal-root.pem".to_string()]
        );
        assert_eq!(ob.tls_ca_pem.len(), 1);
        assert_eq!(
            ob.tls_client_cert_path.as_deref(),
            Some("/path/to/client.crt")
        );
        assert_eq!(
            ob.tls_client_key_path.as_deref(),
            Some("/path/to/client.key")
        );
    }

    #[test]
    fn wp30z_pin_outbound_lowering_owner_is_outbound_rs() {
        let source = include_str!("outbound.rs");
        assert!(
            source.contains("pub(super) fn lower_outbounds"),
            "outbound lowering entry should live in validator/v2/outbound.rs"
        );

        let mut ir = ConfigIR::default();
        let doc = json!({
            "outbounds": [{
                "type": "selector",
                "tag": "manual",
                "outbounds": ["direct"],
                "default": "direct"
            }]
        });
        lower_outbounds(&doc, &mut ir);
        assert_eq!(ir.outbounds.len(), 1);
        assert_eq!(ir.outbounds[0].name.as_deref(), Some("manual"));
        assert_eq!(
            ir.outbounds[0].members.as_ref(),
            Some(&vec!["direct".to_string()])
        );
        assert_eq!(ir.outbounds[0].default_member.as_deref(), Some("direct"));
    }

    #[test]
    fn wp30z_pin_mod_rs_to_ir_v1_delegates_outbounds() {
        let mod_source = include_str!("mod.rs");
        assert!(
            mod_source.contains("facade::to_ir_v1(doc)"),
            "mod.rs to_ir_v1() must remain a thin facade delegate"
        );

        let facade_source = include_str!("facade.rs");
        assert!(
            facade_source.contains("outbound::lower_outbounds(doc, &mut ir);"),
            "facade.rs to_ir_v1() should delegate outbound lowering to outbound::lower_outbounds"
        );
        assert!(
            !facade_source.contains("let mut ob = crate::ir::OutboundIR"),
            "facade.rs should no longer construct OutboundIR inline"
        );
        assert!(
            !facade_source.contains("ir.outbounds.push(ob);"),
            "facade.rs should not push outbound entries directly"
        );

        let doc = json!({
            "schema_version": 2,
            "outbounds": [
                {
                    "type": "urltest",
                    "tag": "auto",
                    "outbounds": ["direct"],
                    "interval": "3s",
                    "timeout": "1500ms",
                    "tolerance": 25
                },
                {
                    "type": "wireguard",
                    "tag": "wg",
                    "local_address": ["10.0.0.2/32"],
                    "peers": [{
                        "public_key": "peer-key",
                        "allowed_ips": ["0.0.0.0/0"],
                        "persistent_keepalive_interval": 20
                    }]
                }
            ]
        });

        let ir_via_to_ir = to_ir_v1(&doc);
        let mut ir_via_lower = ConfigIR::default();
        lower_outbounds(&doc, &mut ir_via_lower);
        assert_eq!(ir_via_to_ir.outbounds, ir_via_lower.outbounds);
    }
}
