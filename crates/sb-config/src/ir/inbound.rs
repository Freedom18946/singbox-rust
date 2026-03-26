//! Inbound IR types (listener config, protocol users, TUN options).

use serde::{Deserialize, Serialize};

use super::{Credentials, MasqueradeIR, MultiplexOptionsIR};

fn default_true() -> bool {
    true
}

/// Inbound proxy type.
/// 入站代理类型。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum InboundType {
    /// SOCKS5 proxy.
    /// SOCKS5 代理。
    #[default]
    Socks,
    /// HTTP CONNECT proxy.
    /// HTTP CONNECT 代理。
    Http,
    /// TUN device inbound.
    /// TUN 设备入站。
    Tun,
    /// Mixed HTTP/SOCKS inbound.
    /// 混合 HTTP/SOCKS 入站。
    Mixed,
    /// Linux REDIRECT (iptables REDIRECT based transparent proxy)
    /// Linux REDIRECT (基于 iptables REDIRECT 的透明代理)
    Redirect,
    /// Linux TProxy (transparent proxy with IP_TRANSPARENT)
    /// Linux TProxy (使用 IP_TRANSPARENT 的透明代理)
    Tproxy,
    /// Direct TCP/UDP forwarder with optional destination override.
    /// 带有可选目标覆盖的直接 TCP/UDP 转发器。
    Direct,
    /// Shadowsocks proxy server.
    /// Shadowsocks 代理服务器。
    Shadowsocks,
    /// VMess proxy server.
    /// VMess 代理服务器。
    Vmess,
    /// VLESS proxy server.
    /// VLESS 代理服务器。
    Vless,
    /// Trojan proxy server.
    /// Trojan 代理服务器。
    Trojan,
    /// Naive proxy server (HTTP/2 CONNECT).
    /// Naive 代理服务器 (HTTP/2 CONNECT)。
    Naive,
    /// ShadowTLS proxy server.
    /// ShadowTLS 代理服务器。
    Shadowtls,
    /// AnyTLS-style protocol server.
    /// AnyTLS 风格的协议服务器。
    Anytls,
    /// Hysteria v1 proxy server.
    /// Hysteria v1 代理服务器。
    Hysteria,
    /// Hysteria v2 proxy server.
    /// Hysteria v2 代理服务器。
    Hysteria2,
    /// TUIC proxy server.
    /// TUIC 代理服务器。
    Tuic,
    /// DNS server inbound.
    /// DNS 服务器入站。
    Dns,
    /// SSH tunnel inbound.
    /// SSH 隧道入站。
    Ssh,
}

impl InboundType {
    /// Return the lowercase string name used in config/registry.
    #[must_use]
    pub fn ty_str(&self) -> &'static str {
        match self {
            InboundType::Socks => "socks",
            InboundType::Http => "http",
            InboundType::Tun => "tun",
            InboundType::Mixed => "mixed",
            InboundType::Redirect => "redirect",
            InboundType::Tproxy => "tproxy",
            InboundType::Direct => "direct",
            InboundType::Shadowsocks => "shadowsocks",
            InboundType::Vmess => "vmess",
            InboundType::Vless => "vless",
            InboundType::Trojan => "trojan",
            InboundType::Naive => "naive",
            InboundType::Shadowtls => "shadowtls",
            InboundType::Anytls => "anytls",
            InboundType::Hysteria => "hysteria",
            InboundType::Hysteria2 => "hysteria2",
            InboundType::Tuic => "tuic",
            InboundType::Dns => "dns",
            InboundType::Ssh => "ssh",
        }
    }
}

/// Shadowsocks user configuration for multi-user inbound.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowsocksUserIR {
    /// User name.
    pub name: String,
    /// User password.
    pub password: String,
}

/// VMess user configuration for multi-user inbound.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VmessUserIR {
    /// User name.
    pub name: String,
    /// User UUID.
    pub uuid: String,
    /// VMess alterId (legacy, usually 0).
    #[serde(default)]
    pub alter_id: u32,
}

/// VLESS user configuration for multi-user inbound.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VlessUserIR {
    /// User name.
    pub name: String,
    /// User UUID.
    pub uuid: String,
    /// VLESS flow control (e.g., "xtls-rprx-vision").
    #[serde(default)]
    pub flow: Option<String>,
    /// VMess/VLESS security parameters
    #[serde(default)]
    pub security: Option<String>,
    /// VMess alterId (legacy)
    #[serde(default)]
    pub alter_id: Option<u8>,
    /// VLESS encryption parameter (e.g., "none")
    #[serde(default)]
    pub encryption: Option<String>,
}

/// Trojan user configuration for multi-user inbound.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrojanUserIR {
    /// User name.
    pub name: String,
    /// User password.
    pub password: String,
}

/// ShadowTLS user configuration for multi-user inbound.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowTlsUserIR {
    /// Optional user name for logging/routing purposes.
    #[serde(default)]
    pub name: String,
    /// User password.
    pub password: String,
}

/// ShadowTLS handshake target configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ShadowTlsHandshakeIR {
    /// Upstream handshake server hostname or IP.
    pub server: String,
    /// Upstream handshake server port.
    #[serde(rename = "server_port")]
    pub server_port: u16,
}

/// AnyTLS user configuration for multi-user inbound.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnyTlsUserIR {
    /// Optional user name for logging/routing purposes.
    #[serde(default)]
    pub name: Option<String>,
    /// User password.
    pub password: String,
}

/// Hysteria2 user configuration for multi-user inbound.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Hysteria2UserIR {
    /// User name.
    pub name: String,
    /// User password.
    pub password: String,
}

/// TUIC user configuration for multi-user inbound.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TuicUserIR {
    /// User UUID.
    pub uuid: String,
    /// User token.
    pub token: String,
}

/// Hysteria v1 user configuration for multi-user inbound.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HysteriaUserIR {
    /// User name.
    pub name: String,
    /// User authentication string.
    pub auth: String,
}

/// Inbound listener configuration.
/// 入站监听器配置。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct InboundIR {
    /// Inbound tag (unique identifier for routing rules, Go parity).
    /// 入站标签（用于路由规则的唯一标识符，Go 对齐）。
    #[serde(default)]
    pub tag: Option<String>,
    /// Inbound type.
    /// 入站类型。
    pub ty: InboundType,
    /// Listen address (IP or hostname).
    /// 监听地址（IP 或主机名）。
    pub listen: String,
    /// Listen port.
    /// 监听端口。
    pub port: u16,
    /// Enable traffic sniffing.
    /// 启用流量嗅探。
    #[serde(default)]
    pub sniff: bool,
    /// Override destination with sniffed hostname (Go parity: sniff_override_destination).
    #[serde(default)]
    pub sniff_override_destination: bool,
    /// Enable UDP support.
    /// 启用 UDP 支持。
    #[serde(default)]
    pub udp: bool,
    /// UDP timeout (e.g. "5m").
    /// UDP 超时（例如 "5m"）。
    #[serde(default)]
    pub udp_timeout: Option<String>,
    /// Detour to another inbound tag.
    #[serde(default)]
    pub detour: Option<String>,
    /// Domain/IP resolution strategy for Socks inbound.
    /// Socks 入站的域名/IP 解析策略。
    #[serde(default)]
    pub domain_strategy: Option<String>,
    /// Basic authentication for HTTP inbound (optional).
    /// HTTP 入站的基本认证（可选）。
    #[serde(default)]
    pub basic_auth: Option<Credentials>,
    /// Generic users list for SOCKS/HTTP/Mixed inbound authentication.
    /// SOCKS/HTTP/Mixed 入站认证的通用用户列表。
    #[serde(default)]
    pub users: Option<Vec<Credentials>>,
    /// Override destination host (for direct inbound).
    /// 覆盖目标主机（用于直接入站）。
    #[serde(default)]
    pub override_host: Option<String>,
    /// Override destination port (for direct inbound).
    /// 覆盖目标端口（用于直接入站）。
    #[serde(default)]
    pub override_port: Option<u16>,

    /// Set system proxy.
    /// 设置系统代理。
    #[serde(default)]
    pub set_system_proxy: bool,

    /// Allow private network access.
    /// 允许访问私有网络。
    #[serde(default = "default_true")]
    pub allow_private_network: bool,

    // Protocol-specific fields (Shadowsocks)
    /// Shadowsocks encryption method (e.g., "aes-256-gcm", "chacha20-poly1305").
    /// Shadowsocks 加密方法（例如 "aes-256-gcm", "chacha20-poly1305"）。
    #[serde(default)]
    pub method: Option<String>,
    /// Shadowsocks password (single-user mode).
    /// Shadowsocks 密码（单用户模式）。
    #[serde(default)]
    pub password: Option<String>,
    /// Shadowsocks multi-user configuration.
    /// Shadowsocks 多用户配置。
    #[serde(default)]
    pub users_shadowsocks: Option<Vec<ShadowsocksUserIR>>,
    /// Network type for Shadowsocks (e.g., "tcp", "udp", "tcp,udp").
    /// Shadowsocks 的网络类型（例如 "tcp", "udp", "tcp,udp"）。
    #[serde(default)]
    pub network: Option<String>,

    // Protocol-specific fields (VMess)
    /// VMess user UUID (single-user mode).
    /// VMess 用户 UUID（单用户模式）。
    #[serde(default)]
    pub uuid: Option<String>,
    /// VMess alterId (legacy, usually 0).
    /// VMess alterId（旧版，通常为 0）。
    #[serde(default)]
    pub alter_id: Option<u32>,
    /// VMess multi-user configuration.
    /// VMess 多用户配置。
    #[serde(default)]
    pub users_vmess: Option<Vec<VmessUserIR>>,
    /// VMess security (e.g., "auto", "aes-128-gcm", "chacha20-poly1305").
    #[serde(default)]
    pub security: Option<String>,

    // Protocol-specific fields (VLESS)
    /// VLESS flow control (e.g., "xtls-rprx-vision").
    /// VLESS 流控（例如 "xtls-rprx-vision"）。
    #[serde(default)]
    pub flow: Option<String>,
    /// VLESS multi-user configuration.
    /// VLESS 多用户配置。
    #[serde(default)]
    pub users_vless: Option<Vec<VlessUserIR>>,

    // Protocol-specific fields (Trojan)
    /// Trojan multi-user configuration.
    /// Trojan 多用户配置。
    #[serde(default)]
    pub users_trojan: Option<Vec<TrojanUserIR>>,
    /// ShadowTLS protocol version.
    #[serde(default)]
    pub version: Option<u8>,
    /// ShadowTLS multi-user configuration.
    #[serde(default)]
    pub users_shadowtls: Option<Vec<ShadowTlsUserIR>>,
    /// ShadowTLS handshake target configuration.
    #[serde(default)]
    pub shadowtls_handshake: Option<ShadowTlsHandshakeIR>,
    /// ShadowTLS handshake target overrides by server name.
    #[serde(default)]
    pub shadowtls_handshake_for_server_name:
        Option<std::collections::HashMap<String, ShadowTlsHandshakeIR>>,
    /// ShadowTLS strict mode (primarily version 3).
    #[serde(default)]
    pub shadowtls_strict_mode: Option<bool>,
    /// ShadowTLS wildcard SNI mode (`off`, `authed`, `all`).
    #[serde(default)]
    pub shadowtls_wildcard_sni: Option<String>,
    /// Trojan fallback target address (e.g. "127.0.0.1:80").
    #[serde(default)]
    pub fallback: Option<String>,
    /// Trojan fallback targets by ALPN.
    #[serde(default)]
    pub fallback_for_alpn: Option<std::collections::HashMap<String, String>>,

    // Protocol-specific fields (AnyTLS)
    /// AnyTLS multi-user configuration.
    /// AnyTLS 多用户配置。
    #[serde(default)]
    pub users_anytls: Option<Vec<AnyTlsUserIR>>,
    /// Optional AnyTLS padding scheme lines (each entry corresponds to a rule row).
    /// 可选的 AnyTLS 填充方案行（每条对应一个规则行）。
    #[serde(default)]
    pub anytls_padding: Option<Vec<String>>,

    // Protocol-specific fields (Hysteria2)
    /// Hysteria2 multi-user configuration.
    /// Hysteria2 多用户配置。
    #[serde(default)]
    pub users_hysteria2: Option<Vec<Hysteria2UserIR>>,
    /// Hysteria2 congestion control algorithm (e.g., "bbr", "cubic", "brutal").
    /// Hysteria2 拥塞控制算法（例如 "bbr", "cubic", "brutal"）。
    #[serde(default)]
    pub congestion_control: Option<String>,
    /// Hysteria2 Salamander obfuscation password.
    /// Hysteria2 Salamander 混淆密码。
    #[serde(default)]
    pub salamander: Option<String>,
    /// Hysteria2 obfuscation key.
    /// Hysteria2 混淆密钥。
    #[serde(default)]
    pub obfs: Option<String>,
    /// Hysteria2 Brutal congestion control upload limit (Mbps).
    /// Hysteria2 Brutal 拥塞控制上传限制 (Mbps)。
    #[serde(default)]
    pub brutal_up_mbps: Option<u32>,
    /// Hysteria2 Brutal congestion control download limit (Mbps).
    /// Hysteria2 Brutal 拥塞控制下载限制 (Mbps)。
    #[serde(default)]
    pub brutal_down_mbps: Option<u32>,
    /// Hysteria2 Masquerade configuration.
    /// Hysteria2 Masquerade 配置。
    #[serde(default)]
    pub masquerade: Option<MasqueradeIR>,

    // Protocol-specific fields (TUIC)
    /// TUIC multi-user configuration.
    /// TUIC 多用户配置。
    #[serde(default)]
    pub users_tuic: Option<Vec<TuicUserIR>>,

    // Protocol-specific fields (Hysteria v1)
    /// Hysteria v1 multi-user configuration.
    /// Hysteria v1 多用户配置。
    #[serde(default)]
    pub users_hysteria: Option<Vec<HysteriaUserIR>>,
    /// Hysteria v1 protocol type ("udp", "wechat-video", "faketcp").
    /// Hysteria v1 协议类型 ("udp", "wechat-video", "faketcp")。
    #[serde(default)]
    pub hysteria_protocol: Option<String>,
    /// Hysteria v1 obfuscation password.
    /// Hysteria v1 混淆密码。
    #[serde(default)]
    pub hysteria_obfs: Option<String>,
    /// Hysteria v1 upload bandwidth (Mbps).
    /// Hysteria v1 上传带宽 (Mbps)。
    #[serde(default)]
    pub hysteria_up_mbps: Option<u32>,
    /// Hysteria v1 download bandwidth (Mbps).
    /// Hysteria v1 下载带宽 (Mbps)。
    #[serde(default)]
    pub hysteria_down_mbps: Option<u32>,
    /// Hysteria v1 QUIC receive window for connection.
    /// Hysteria v1 连接的 QUIC 接收窗口。
    #[serde(default)]
    pub hysteria_recv_window_conn: Option<u64>,
    /// Hysteria v1 QUIC receive window for stream.
    /// Hysteria v1 流的 QUIC 接收窗口。
    #[serde(default)]
    pub hysteria_recv_window: Option<u64>,

    // Transport and security options (V2Ray protocols)
    /// Transport layer chain (e.g., ["tls", "ws"] for WebSocket over TLS).
    /// 传输层链（例如 ["tls", "ws"] 表示 WebSocket over TLS）。
    #[serde(default)]
    pub transport: Option<Vec<String>>,
    /// WebSocket path.
    /// WebSocket 路径。
    #[serde(default)]
    pub ws_path: Option<String>,
    /// WebSocket Host header.
    /// WebSocket Host 头。
    #[serde(default)]
    pub ws_host: Option<String>,
    /// HTTP/2 path.
    /// HTTP/2 路径。
    #[serde(default)]
    pub h2_path: Option<String>,
    /// HTTP/2 Host header.
    /// HTTP/2 Host 头。
    #[serde(default)]
    pub h2_host: Option<String>,
    /// gRPC service name.
    /// gRPC 服务名称。
    #[serde(default)]
    pub grpc_service: Option<String>,

    // TLS options
    /// Enable TLS for this inbound.
    /// 为此入站启用 TLS。
    #[serde(default)]
    pub tls_enabled: Option<bool>,
    /// Path to TLS certificate file (PEM format).
    /// TLS 证书文件路径（PEM 格式）。
    #[serde(default)]
    pub tls_cert_path: Option<String>,
    /// Path to TLS private key file (PEM format).
    /// TLS 私钥文件路径（PEM 格式）。
    #[serde(default)]
    pub tls_key_path: Option<String>,
    /// Inline TLS certificate (PEM format).
    /// 内联 TLS 证书（PEM 格式）。
    #[serde(default)]
    pub tls_cert_pem: Option<String>,
    /// Inline TLS private key (PEM format).
    /// 内联 TLS 私钥（PEM 格式）。
    #[serde(default)]
    pub tls_key_pem: Option<String>,
    /// TLS server name (SNI).
    /// TLS 服务器名称 (SNI)。
    #[serde(default)]
    pub tls_server_name: Option<String>,
    /// TLS ALPN protocols.
    /// TLS ALPN 协议。
    pub tls_alpn: Option<Vec<String>>,

    // Multiplex options
    /// Multiplex configuration for stream multiplexing.
    /// 流多路复用的多路复用配置。
    #[serde(default)]
    pub multiplex: Option<MultiplexOptionsIR>,

    // Tun options
    /// Tun interface configuration.
    #[serde(default)]
    pub tun: Option<TunOptionsIR>,

    // SSH options
    /// SSH server host key file path (PEM format).
    /// SSH 服务器主机密钥文件路径（PEM 格式）。
    #[serde(default)]
    pub ssh_host_key_path: Option<String>,
}

/// Tun inbound options.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct TunOptionsIR {
    #[serde(default)]
    pub platform: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub mtu: Option<u32>,
    #[serde(default)]
    pub dry_run: Option<bool>,
    #[serde(default)]
    pub user_tag: Option<String>,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub auto_route: Option<bool>,
    #[serde(default)]
    pub auto_redirect: Option<bool>,
    #[serde(default)]
    pub strict_route: Option<bool>,
    #[serde(default)]
    pub inet4_address: Option<String>,
    #[serde(default)]
    pub inet6_address: Option<String>,
    #[serde(default)]
    pub table_id: Option<u32>,
    #[serde(default)]
    pub fwmark: Option<u32>,
    #[serde(default)]
    pub exclude_routes: Option<Vec<String>>,
    #[serde(default)]
    pub include_routes: Option<Vec<String>>,
    #[serde(default)]
    pub exclude_uids: Option<Vec<u32>>,
    #[serde(default)]
    pub stack: Option<String>,
    #[serde(default)]
    pub endpoint_independent_nat: Option<bool>,
    #[serde(default)]
    pub udp_timeout: Option<String>,
    #[serde(default)]
    pub exclude_processes: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // ── InboundType serde + ty_str ──────────────────────────────────

    #[test]
    fn inbound_type_serde_all_variants() {
        let cases = [
            ("\"socks\"", InboundType::Socks),
            ("\"http\"", InboundType::Http),
            ("\"tun\"", InboundType::Tun),
            ("\"mixed\"", InboundType::Mixed),
            ("\"redirect\"", InboundType::Redirect),
            ("\"tproxy\"", InboundType::Tproxy),
            ("\"direct\"", InboundType::Direct),
            ("\"shadowsocks\"", InboundType::Shadowsocks),
            ("\"vmess\"", InboundType::Vmess),
            ("\"vless\"", InboundType::Vless),
            ("\"trojan\"", InboundType::Trojan),
            ("\"naive\"", InboundType::Naive),
            ("\"shadowtls\"", InboundType::Shadowtls),
            ("\"anytls\"", InboundType::Anytls),
            ("\"hysteria\"", InboundType::Hysteria),
            ("\"hysteria2\"", InboundType::Hysteria2),
            ("\"tuic\"", InboundType::Tuic),
            ("\"dns\"", InboundType::Dns),
            ("\"ssh\"", InboundType::Ssh),
        ];
        for (json_str, expected) in &cases {
            let parsed: InboundType = serde_json::from_str(json_str).unwrap();
            assert_eq!(&parsed, expected, "deserialize {json_str}");
            // roundtrip
            let rt_json = serde_json::to_string(&parsed).unwrap();
            let rt: InboundType = serde_json::from_str(&rt_json).unwrap();
            assert_eq!(&rt, expected, "roundtrip {json_str}");
        }
    }

    #[test]
    fn inbound_type_ty_str() {
        assert_eq!(InboundType::Socks.ty_str(), "socks");
        assert_eq!(InboundType::Http.ty_str(), "http");
        assert_eq!(InboundType::Tun.ty_str(), "tun");
        assert_eq!(InboundType::Mixed.ty_str(), "mixed");
        assert_eq!(InboundType::Redirect.ty_str(), "redirect");
        assert_eq!(InboundType::Tproxy.ty_str(), "tproxy");
        assert_eq!(InboundType::Direct.ty_str(), "direct");
        assert_eq!(InboundType::Shadowsocks.ty_str(), "shadowsocks");
        assert_eq!(InboundType::Vmess.ty_str(), "vmess");
        assert_eq!(InboundType::Vless.ty_str(), "vless");
        assert_eq!(InboundType::Trojan.ty_str(), "trojan");
        assert_eq!(InboundType::Naive.ty_str(), "naive");
        assert_eq!(InboundType::Shadowtls.ty_str(), "shadowtls");
        assert_eq!(InboundType::Anytls.ty_str(), "anytls");
        assert_eq!(InboundType::Hysteria.ty_str(), "hysteria");
        assert_eq!(InboundType::Hysteria2.ty_str(), "hysteria2");
        assert_eq!(InboundType::Tuic.ty_str(), "tuic");
        assert_eq!(InboundType::Dns.ty_str(), "dns");
        assert_eq!(InboundType::Ssh.ty_str(), "ssh");
    }

    #[test]
    fn inbound_type_default_is_socks() {
        assert_eq!(InboundType::default(), InboundType::Socks);
    }

    // ── InboundIR roundtrip ─────────────────────────────────────────

    #[test]
    fn inbound_ir_basic_roundtrip() {
        let data = json!({
            "ty": "http",
            "listen": "127.0.0.1",
            "port": 8080,
            "sniff": true,
            "sniff_override_destination": true,
            "udp": false,
            "tag": "http-in",
            "set_system_proxy": true
        });
        let ir: InboundIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.ty, InboundType::Http);
        assert_eq!(ir.listen, "127.0.0.1");
        assert_eq!(ir.port, 8080);
        assert!(ir.sniff);
        assert!(ir.sniff_override_destination);
        assert!(!ir.udp);
        assert_eq!(ir.tag.as_deref(), Some("http-in"));
        assert!(ir.set_system_proxy);
        // allow_private_network defaults to true
        assert!(ir.allow_private_network);

        // roundtrip
        let rt: InboundIR = serde_json::from_value(serde_json::to_value(&ir).unwrap()).unwrap();
        assert_eq!(rt.ty, ir.ty);
        assert_eq!(rt.listen, ir.listen);
        assert_eq!(rt.port, ir.port);
        assert_eq!(rt.tag, ir.tag);
    }

    #[test]
    fn inbound_ir_allow_private_network_default_true() {
        // When allow_private_network is absent, it should default to true
        let data = json!({
            "ty": "socks",
            "listen": "0.0.0.0",
            "port": 1080
        });
        let ir: InboundIR = serde_json::from_value(data).unwrap();
        assert!(ir.allow_private_network);

        // When explicitly set to false
        let data = json!({
            "ty": "socks",
            "listen": "0.0.0.0",
            "port": 1080,
            "allow_private_network": false
        });
        let ir: InboundIR = serde_json::from_value(data).unwrap();
        assert!(!ir.allow_private_network);
    }

    // ── basic_auth / users authentication ───────────────────────────

    #[test]
    fn inbound_ir_basic_auth_credentials() {
        let data = json!({
            "ty": "http",
            "listen": "0.0.0.0",
            "port": 8080,
            "basic_auth": {
                "username": "admin",
                "password": "secret"
            }
        });
        let ir: InboundIR = serde_json::from_value(data).unwrap();
        let auth = ir.basic_auth.as_ref().unwrap();
        assert_eq!(auth.username.as_deref(), Some("admin"));
        assert_eq!(auth.password.as_deref(), Some("secret"));

        // roundtrip
        let rt: InboundIR = serde_json::from_value(serde_json::to_value(&ir).unwrap()).unwrap();
        assert_eq!(
            rt.basic_auth.as_ref().unwrap().username,
            ir.basic_auth.as_ref().unwrap().username
        );
    }

    #[test]
    fn inbound_ir_users_list() {
        let data = json!({
            "ty": "mixed",
            "listen": "0.0.0.0",
            "port": 1080,
            "users": [
                {"username": "user1", "password": "pass1"},
                {"username": "user2", "password_env": "MY_PASS"}
            ]
        });
        let ir: InboundIR = serde_json::from_value(data).unwrap();
        let users = ir.users.as_ref().unwrap();
        assert_eq!(users.len(), 2);
        assert_eq!(users[0].username.as_deref(), Some("user1"));
        assert_eq!(users[0].password.as_deref(), Some("pass1"));
        assert_eq!(users[1].password_env.as_deref(), Some("MY_PASS"));
    }

    // ── Multi-user protocol fields ──────────────────────────────────

    #[test]
    fn inbound_ir_shadowsocks_users_roundtrip() {
        let data = json!({
            "ty": "shadowsocks",
            "listen": "0.0.0.0",
            "port": 8388,
            "method": "aes-256-gcm",
            "password": "single-user-pass",
            "network": "tcp,udp",
            "users_shadowsocks": [
                {"name": "alice", "password": "alicepw"},
                {"name": "bob", "password": "bobpw"}
            ]
        });
        let ir: InboundIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.ty, InboundType::Shadowsocks);
        assert_eq!(ir.method.as_deref(), Some("aes-256-gcm"));
        assert_eq!(ir.password.as_deref(), Some("single-user-pass"));
        assert_eq!(ir.network.as_deref(), Some("tcp,udp"));
        let users = ir.users_shadowsocks.as_ref().unwrap();
        assert_eq!(users.len(), 2);
        assert_eq!(users[0].name, "alice");
        assert_eq!(users[1].password, "bobpw");

        let rt: InboundIR = serde_json::from_value(serde_json::to_value(&ir).unwrap()).unwrap();
        assert_eq!(rt.users_shadowsocks.as_ref().unwrap().len(), 2);
    }

    #[test]
    fn inbound_ir_vmess_users_roundtrip() {
        let data = json!({
            "ty": "vmess",
            "listen": "0.0.0.0",
            "port": 10086,
            "uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "alter_id": 0,
            "security": "auto",
            "users_vmess": [
                {"name": "user1", "uuid": "11111111-2222-3333-4444-555555555555", "alter_id": 0}
            ]
        });
        let ir: InboundIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.ty, InboundType::Vmess);
        assert_eq!(
            ir.uuid.as_deref(),
            Some("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        );
        assert_eq!(ir.alter_id, Some(0));
        let users = ir.users_vmess.as_ref().unwrap();
        assert_eq!(users[0].name, "user1");
        assert_eq!(users[0].alter_id, 0);

        let rt: InboundIR = serde_json::from_value(serde_json::to_value(&ir).unwrap()).unwrap();
        assert_eq!(rt.uuid, ir.uuid);
    }

    #[test]
    fn inbound_ir_vless_users_roundtrip() {
        let data = json!({
            "ty": "vless",
            "listen": "0.0.0.0",
            "port": 443,
            "users_vless": [
                {
                    "name": "user1",
                    "uuid": "11111111-2222-3333-4444-555555555555",
                    "flow": "xtls-rprx-vision",
                    "security": "auto",
                    "encryption": "none"
                }
            ]
        });
        let ir: InboundIR = serde_json::from_value(data).unwrap();
        let users = ir.users_vless.as_ref().unwrap();
        assert_eq!(users[0].flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(users[0].security.as_deref(), Some("auto"));
        assert_eq!(users[0].encryption.as_deref(), Some("none"));

        let rt: InboundIR = serde_json::from_value(serde_json::to_value(&ir).unwrap()).unwrap();
        assert_eq!(rt.users_vless.as_ref().unwrap()[0].flow, users[0].flow);
    }

    #[test]
    fn inbound_ir_trojan_users_roundtrip() {
        let data = json!({
            "ty": "trojan",
            "listen": "0.0.0.0",
            "port": 443,
            "users_trojan": [
                {"name": "user1", "password": "trojanpass"}
            ],
            "fallback": "127.0.0.1:80",
            "fallback_for_alpn": {"h2": "127.0.0.1:8080"}
        });
        let ir: InboundIR = serde_json::from_value(data).unwrap();
        let users = ir.users_trojan.as_ref().unwrap();
        assert_eq!(users[0].name, "user1");
        assert_eq!(users[0].password, "trojanpass");
        assert_eq!(ir.fallback.as_deref(), Some("127.0.0.1:80"));
        let alpn_fb = ir.fallback_for_alpn.as_ref().unwrap();
        assert_eq!(
            alpn_fb.get("h2").map(String::as_str),
            Some("127.0.0.1:8080")
        );

        let rt: InboundIR = serde_json::from_value(serde_json::to_value(&ir).unwrap()).unwrap();
        assert_eq!(rt.fallback, ir.fallback);
    }

    // ── ShadowTLS ───────────────────────────────────────────────────

    #[test]
    fn inbound_ir_shadowtls_roundtrip() {
        let data = json!({
            "ty": "shadowtls",
            "listen": "0.0.0.0",
            "port": 443,
            "version": 3,
            "users_shadowtls": [
                {"name": "user1", "password": "stlspass"}
            ],
            "shadowtls_handshake": {
                "server": "www.example.com",
                "server_port": 443
            },
            "shadowtls_handshake_for_server_name": {
                "alt.example.com": {
                    "server": "alt.example.com",
                    "server_port": 443
                }
            },
            "shadowtls_strict_mode": true,
            "shadowtls_wildcard_sni": "authed"
        });
        let ir: InboundIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.version, Some(3));
        let users = ir.users_shadowtls.as_ref().unwrap();
        assert_eq!(users[0].name, "user1");
        assert_eq!(users[0].password, "stlspass");
        let hs = ir.shadowtls_handshake.as_ref().unwrap();
        assert_eq!(hs.server, "www.example.com");
        assert_eq!(hs.server_port, 443);
        let hs_map = ir.shadowtls_handshake_for_server_name.as_ref().unwrap();
        assert!(hs_map.contains_key("alt.example.com"));
        assert_eq!(ir.shadowtls_strict_mode, Some(true));
        assert_eq!(ir.shadowtls_wildcard_sni.as_deref(), Some("authed"));

        // roundtrip
        let rt: InboundIR = serde_json::from_value(serde_json::to_value(&ir).unwrap()).unwrap();
        assert_eq!(rt.version, ir.version);
        assert_eq!(rt.shadowtls_handshake.as_ref().unwrap().server, hs.server);
    }

    #[test]
    fn shadowtls_handshake_ir_server_port_rename() {
        // Verify "server_port" JSON key maps correctly
        let data = json!({"server": "test.com", "server_port": 8443});
        let hs: ShadowTlsHandshakeIR = serde_json::from_value(data).unwrap();
        assert_eq!(hs.server, "test.com");
        assert_eq!(hs.server_port, 8443);
        let rt = serde_json::to_value(&hs).unwrap();
        assert_eq!(rt["server_port"], 8443);
        assert!(rt.get("port").is_none()); // not "port"
    }

    // ── TunOptionsIR ────────────────────────────────────────────────

    #[test]
    fn tun_options_ir_roundtrip() {
        let data = json!({
            "platform": "linux",
            "name": "tun0",
            "mtu": 1500,
            "dry_run": false,
            "auto_route": true,
            "auto_redirect": false,
            "strict_route": true,
            "inet4_address": "172.19.0.1/30",
            "inet6_address": "fdfe:dcba:9876::1/126",
            "table_id": 200,
            "fwmark": 51820,
            "exclude_routes": ["192.168.0.0/16"],
            "include_routes": ["10.0.0.0/8"],
            "exclude_uids": [1000],
            "stack": "system",
            "endpoint_independent_nat": true,
            "udp_timeout": "5m",
            "exclude_processes": ["sshd"]
        });
        let ir: TunOptionsIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.platform.as_deref(), Some("linux"));
        assert_eq!(ir.name.as_deref(), Some("tun0"));
        assert_eq!(ir.mtu, Some(1500));
        assert_eq!(ir.dry_run, Some(false));
        assert_eq!(ir.auto_route, Some(true));
        assert_eq!(ir.auto_redirect, Some(false));
        assert_eq!(ir.strict_route, Some(true));
        assert_eq!(ir.inet4_address.as_deref(), Some("172.19.0.1/30"));
        assert_eq!(ir.inet6_address.as_deref(), Some("fdfe:dcba:9876::1/126"));
        assert_eq!(ir.table_id, Some(200));
        assert_eq!(ir.fwmark, Some(51820));
        assert_eq!(
            ir.exclude_routes.as_deref(),
            Some(&["192.168.0.0/16".to_string()][..])
        );
        assert_eq!(
            ir.include_routes.as_deref(),
            Some(&["10.0.0.0/8".to_string()][..])
        );
        assert_eq!(ir.exclude_uids.as_deref(), Some(&[1000u32][..]));
        assert_eq!(ir.stack.as_deref(), Some("system"));
        assert_eq!(ir.endpoint_independent_nat, Some(true));
        assert_eq!(ir.udp_timeout.as_deref(), Some("5m"));
        assert_eq!(
            ir.exclude_processes.as_deref(),
            Some(&["sshd".to_string()][..])
        );

        // roundtrip
        let rt: TunOptionsIR = serde_json::from_value(serde_json::to_value(&ir).unwrap()).unwrap();
        assert_eq!(rt.name, ir.name);
        assert_eq!(rt.mtu, ir.mtu);
        assert_eq!(rt.fwmark, ir.fwmark);
        assert_eq!(rt.exclude_routes, ir.exclude_routes);
    }

    #[test]
    fn tun_options_ir_empty_default() {
        let ir = TunOptionsIR::default();
        assert!(ir.platform.is_none());
        assert!(ir.name.is_none());
        assert!(ir.mtu.is_none());
        assert!(ir.auto_route.is_none());

        let rt: TunOptionsIR = serde_json::from_value(serde_json::to_value(&ir).unwrap()).unwrap();
        assert!(rt.name.is_none());
    }

    // ── InboundIR with TUN nested ───────────────────────────────────

    #[test]
    fn inbound_ir_tun_nested_roundtrip() {
        let data = json!({
            "ty": "tun",
            "listen": "0.0.0.0",
            "port": 0,
            "tun": {
                "name": "utun5",
                "mtu": 9000,
                "auto_route": true,
                "strict_route": true,
                "inet4_address": "172.19.0.1/30",
                "stack": "gvisor"
            }
        });
        let ir: InboundIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.ty, InboundType::Tun);
        let tun = ir.tun.as_ref().unwrap();
        assert_eq!(tun.name.as_deref(), Some("utun5"));
        assert_eq!(tun.mtu, Some(9000));
        assert_eq!(tun.auto_route, Some(true));
        assert_eq!(tun.stack.as_deref(), Some("gvisor"));

        let rt: InboundIR = serde_json::from_value(serde_json::to_value(&ir).unwrap()).unwrap();
        assert_eq!(rt.tun.as_ref().unwrap().name, tun.name);
    }

    // ── Hysteria2 inbound ───────────────────────────────────────────

    #[test]
    fn inbound_ir_hysteria2_roundtrip() {
        let data = json!({
            "ty": "hysteria2",
            "listen": "0.0.0.0",
            "port": 443,
            "users_hysteria2": [
                {"name": "user1", "password": "hy2pass"}
            ],
            "congestion_control": "bbr",
            "salamander": "obfs-key",
            "obfs": "xplus",
            "brutal_up_mbps": 100,
            "brutal_down_mbps": 200,
            "masquerade": {
                "type": "proxy",
                "proxy": {"url": "https://example.com", "rewrite_host": true}
            }
        });
        let ir: InboundIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.ty, InboundType::Hysteria2);
        let users = ir.users_hysteria2.as_ref().unwrap();
        assert_eq!(users[0].name, "user1");
        assert_eq!(ir.congestion_control.as_deref(), Some("bbr"));
        assert_eq!(ir.salamander.as_deref(), Some("obfs-key"));
        assert_eq!(ir.brutal_up_mbps, Some(100));
        assert_eq!(ir.brutal_down_mbps, Some(200));
        let masq = ir.masquerade.as_ref().unwrap();
        assert_eq!(masq.type_, "proxy");
        assert!(masq.proxy.as_ref().unwrap().rewrite_host);

        let rt: InboundIR = serde_json::from_value(serde_json::to_value(&ir).unwrap()).unwrap();
        assert_eq!(rt.users_hysteria2.as_ref().unwrap().len(), 1);
        assert_eq!(rt.masquerade.as_ref().unwrap().type_, "proxy");
    }

    // ── TUIC inbound ────────────────────────────────────────────────

    #[test]
    fn inbound_ir_tuic_roundtrip() {
        let data = json!({
            "ty": "tuic",
            "listen": "0.0.0.0",
            "port": 443,
            "users_tuic": [
                {"uuid": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "token": "mytoken"}
            ]
        });
        let ir: InboundIR = serde_json::from_value(data).unwrap();
        let users = ir.users_tuic.as_ref().unwrap();
        assert_eq!(users[0].uuid, "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
        assert_eq!(users[0].token, "mytoken");

        let rt: InboundIR = serde_json::from_value(serde_json::to_value(&ir).unwrap()).unwrap();
        assert_eq!(rt.users_tuic.as_ref().unwrap()[0].token, "mytoken");
    }

    // ── Hysteria v1 inbound ─────────────────────────────────────────

    #[test]
    fn inbound_ir_hysteria_v1_roundtrip() {
        let data = json!({
            "ty": "hysteria",
            "listen": "0.0.0.0",
            "port": 443,
            "users_hysteria": [
                {"name": "user1", "auth": "authstring"}
            ],
            "hysteria_protocol": "udp",
            "hysteria_obfs": "obfs-pw",
            "hysteria_up_mbps": 50,
            "hysteria_down_mbps": 100,
            "hysteria_recv_window_conn": 15728640,
            "hysteria_recv_window": 6291456
        });
        let ir: InboundIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.ty, InboundType::Hysteria);
        let users = ir.users_hysteria.as_ref().unwrap();
        assert_eq!(users[0].auth, "authstring");
        assert_eq!(ir.hysteria_protocol.as_deref(), Some("udp"));
        assert_eq!(ir.hysteria_obfs.as_deref(), Some("obfs-pw"));
        assert_eq!(ir.hysteria_up_mbps, Some(50));
        assert_eq!(ir.hysteria_down_mbps, Some(100));
        assert_eq!(ir.hysteria_recv_window_conn, Some(15_728_640));
        assert_eq!(ir.hysteria_recv_window, Some(6_291_456));

        let rt: InboundIR = serde_json::from_value(serde_json::to_value(&ir).unwrap()).unwrap();
        assert_eq!(rt.hysteria_recv_window_conn, ir.hysteria_recv_window_conn);
    }

    // ── AnyTLS inbound ──────────────────────────────────────────────

    #[test]
    fn inbound_ir_anytls_roundtrip() {
        let data = json!({
            "ty": "anytls",
            "listen": "0.0.0.0",
            "port": 443,
            "users_anytls": [
                {"name": "user1", "password": "anytlspw"}
            ],
            "anytls_padding": ["0-100", "100-200"]
        });
        let ir: InboundIR = serde_json::from_value(data).unwrap();
        let users = ir.users_anytls.as_ref().unwrap();
        assert_eq!(users[0].name.as_deref(), Some("user1"));
        assert_eq!(users[0].password, "anytlspw");
        assert_eq!(ir.anytls_padding.as_ref().unwrap().len(), 2);

        let rt: InboundIR = serde_json::from_value(serde_json::to_value(&ir).unwrap()).unwrap();
        assert_eq!(rt.anytls_padding, ir.anytls_padding);
    }

    // ── Transport and TLS fields ────────────────────────────────────

    #[test]
    fn inbound_ir_transport_tls_fields() {
        let data = json!({
            "ty": "vmess",
            "listen": "0.0.0.0",
            "port": 443,
            "transport": ["tls", "ws"],
            "ws_path": "/vmess",
            "ws_host": "example.com",
            "tls_enabled": true,
            "tls_cert_path": "/etc/ssl/cert.pem",
            "tls_key_path": "/etc/ssl/key.pem",
            "tls_server_name": "example.com",
            "tls_alpn": ["h2", "http/1.1"]
        });
        let ir: InboundIR = serde_json::from_value(data).unwrap();
        assert_eq!(
            ir.transport.as_deref(),
            Some(&["tls".to_string(), "ws".to_string()][..])
        );
        assert_eq!(ir.ws_path.as_deref(), Some("/vmess"));
        assert_eq!(ir.ws_host.as_deref(), Some("example.com"));
        assert_eq!(ir.tls_enabled, Some(true));
        assert_eq!(ir.tls_cert_path.as_deref(), Some("/etc/ssl/cert.pem"));
        assert_eq!(ir.tls_server_name.as_deref(), Some("example.com"));
        assert_eq!(ir.tls_alpn.as_ref().unwrap().len(), 2);
    }

    // ── SSH inbound ─────────────────────────────────────────────────

    #[test]
    fn inbound_ir_ssh_host_key() {
        let data = json!({
            "ty": "ssh",
            "listen": "0.0.0.0",
            "port": 2222,
            "ssh_host_key_path": "/etc/ssh/host_key"
        });
        let ir: InboundIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.ty, InboundType::Ssh);
        assert_eq!(ir.ssh_host_key_path.as_deref(), Some("/etc/ssh/host_key"));
    }
}
