//! Service IR types (Resolved, DERP, SSM-API).

use serde::{Deserialize, Serialize};

use super::{
    raw::{
        RawDerpDialOptionsIR, RawDerpDomainResolverIR, RawDerpMeshPeerIR,
        RawDerpOutboundTlsOptionsIR, RawDerpStunOptionsIR, RawDerpVerifyClientUrlIR,
        RawInboundTlsOptionsIR,
    },
    Listable, StringOrObj,
};

/// Inbound TLS options (Go parity: `option.InboundTLSOptions`).
/// 入站 TLS 选项（对齐 Go `option.InboundTLSOptions`）。
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct InboundTlsOptionsIR {
    /// Enable TLS (Go: `enabled`).
    /// 启用 TLS（Go: `enabled`）。
    #[serde(default)]
    pub enabled: bool,
    /// Server name (SNI) used for verification (client-side).
    /// 用于校验的服务器名 (SNI)（客户端）。
    #[serde(default)]
    pub server_name: Option<String>,
    /// Accept any certificate (client-side).
    /// 接受任意证书（客户端）。
    #[serde(default)]
    pub insecure: Option<bool>,
    /// ALPN protocol list.
    /// ALPN 协议列表。
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
    /// Minimum TLS version (e.g. "1.2").
    /// 最小 TLS 版本（例如 "1.2"）。
    #[serde(default)]
    pub min_version: Option<String>,
    /// Maximum TLS version (e.g. "1.3").
    /// 最大 TLS 版本（例如 "1.3"）。
    #[serde(default)]
    pub max_version: Option<String>,
    /// TLS 1.0–1.2 cipher suites list.
    /// TLS 1.0–1.2 密码套件列表。
    #[serde(default)]
    pub cipher_suites: Option<Vec<String>>,
    /// Inline server certificate line array (PEM).
    /// 内联服务端证书行数组（PEM）。
    #[serde(default)]
    pub certificate: Option<Vec<String>>,
    /// Server certificate path (PEM).
    /// 服务端证书路径（PEM）。
    #[serde(default)]
    pub certificate_path: Option<String>,
    /// Inline server private key line array (PEM).
    /// 内联服务端私钥行数组（PEM）。
    #[serde(default)]
    pub key: Option<Vec<String>>,
    /// Server private key path (PEM).
    /// 服务端私钥路径（PEM）。
    #[serde(default)]
    pub key_path: Option<String>,
    // ACME/ECH/Reality fields are intentionally omitted for now; they will be
    // added when the corresponding runtime integrations land.
}

impl<'de> Deserialize<'de> for InboundTlsOptionsIR {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        RawInboundTlsOptionsIR::deserialize(deserializer).map(Into::into)
    }
}

/// DERP STUN listen options (Go parity: `option.DERPSTUNListenOptions`).
/// DERP STUN 监听选项（对齐 Go `option.DERPSTUNListenOptions`）。
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct DerpStunOptionsIR {
    /// Enable STUN server.
    /// 启用 STUN 服务。
    #[serde(default)]
    pub enabled: bool,
    /// Listen address.
    /// 监听地址。
    #[serde(default)]
    pub listen: Option<String>,
    /// Listen port.
    /// 监听端口。
    #[serde(default)]
    pub listen_port: Option<u16>,
    /// Bind interface (Linux).
    /// 绑定网卡（Linux）。
    #[serde(default)]
    pub bind_interface: Option<String>,
    /// Routing mark (Linux).
    /// 路由标记（Linux）。
    #[serde(default)]
    pub routing_mark: Option<u32>,
    /// Reuse address.
    /// 复用地址。
    #[serde(default)]
    pub reuse_addr: Option<bool>,
    /// Network namespace name/path (Linux).
    /// 网络命名空间名称/路径（Linux）。
    #[serde(default)]
    pub netns: Option<String>,
}

impl<'de> Deserialize<'de> for DerpStunOptionsIR {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        RawDerpStunOptionsIR::deserialize(deserializer).map(Into::into)
    }
}

/// DERP Dial domain_resolver options (subset; Go parity: Dial Fields `domain_resolver`).
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct DerpDomainResolverIR {
    /// DNS server tag.
    #[serde(default)]
    pub server: Option<String>,
    /// Strategy hint (parsed but not necessarily honored in runtime).
    #[serde(default)]
    pub strategy: Option<String>,
    /// Forward-compatible extra fields.
    #[serde(default, flatten)]
    pub extra: std::collections::BTreeMap<String, serde_json::Value>,
}

impl From<String> for DerpDomainResolverIR {
    fn from(s: String) -> Self {
        Self {
            server: Some(s),
            ..Default::default()
        }
    }
}

impl<'de> Deserialize<'de> for DerpDomainResolverIR {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        RawDerpDomainResolverIR::deserialize(deserializer).map(Into::into)
    }
}

/// DERP Dial Fields (Go parity: shared/dial.md) used by verify_client_url and mesh_with.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct DerpDialOptionsIR {
    #[serde(default)]
    pub detour: Option<String>,
    #[serde(default)]
    pub bind_interface: Option<String>,
    #[serde(default)]
    pub inet4_bind_address: Option<String>,
    #[serde(default)]
    pub inet6_bind_address: Option<String>,
    #[serde(default)]
    pub routing_mark: Option<u32>,
    #[serde(default)]
    pub reuse_addr: Option<bool>,
    #[serde(default)]
    pub netns: Option<String>,
    #[serde(default)]
    pub connect_timeout: Option<String>,
    #[serde(default)]
    pub tcp_fast_open: Option<bool>,
    #[serde(default)]
    pub tcp_multi_path: Option<bool>,
    #[serde(default)]
    pub udp_fragment: Option<bool>,
    #[serde(default)]
    pub domain_resolver: Option<StringOrObj<DerpDomainResolverIR>>,
    /// Forward-compatible extra fields (network_strategy, etc.).
    #[serde(default, flatten)]
    pub extra: std::collections::BTreeMap<String, serde_json::Value>,
}

impl<'de> Deserialize<'de> for DerpDialOptionsIR {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        RawDerpDialOptionsIR::deserialize(deserializer).map(Into::into)
    }
}

/// DERP verify_client_url options (Go parity: option.DERPVerifyClientURLOptions).
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct DerpVerifyClientUrlIR {
    #[serde(default)]
    pub url: String,
    #[serde(default, flatten)]
    pub dial: DerpDialOptionsIR,
}

impl From<String> for DerpVerifyClientUrlIR {
    fn from(s: String) -> Self {
        Self {
            url: s,
            ..Default::default()
        }
    }
}

impl<'de> Deserialize<'de> for DerpVerifyClientUrlIR {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        RawDerpVerifyClientUrlIR::deserialize(deserializer).map(Into::into)
    }
}

/// DERP mesh peer outbound TLS options (minimal subset).
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct DerpOutboundTlsOptionsIR {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub insecure: Option<bool>,
    #[serde(default)]
    pub alpn: Option<Vec<String>>,
    #[serde(default)]
    pub ca_paths: Vec<String>,
    #[serde(default)]
    pub ca_pem: Vec<String>,
}

impl<'de> Deserialize<'de> for DerpOutboundTlsOptionsIR {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        RawDerpOutboundTlsOptionsIR::deserialize(deserializer).map(Into::into)
    }
}

/// DERP mesh peer options (Go parity: option.DERPMeshOptions).
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct DerpMeshPeerIR {
    /// DERP server address (host or ip).
    #[serde(default)]
    pub server: String,
    /// DERP server port.
    #[serde(default)]
    pub server_port: Option<u16>,
    /// Optional hostname override for SNI/Host.
    #[serde(default)]
    pub host: Option<String>,
    /// Optional per-peer TLS options.
    #[serde(default)]
    pub tls: Option<DerpOutboundTlsOptionsIR>,
    /// Dial Fields.
    #[serde(default, flatten)]
    pub dial: DerpDialOptionsIR,
}

impl From<String> for DerpMeshPeerIR {
    fn from(s: String) -> Self {
        // Parse `host:port` shorthand when possible; keep raw as server otherwise.
        let mut out = Self {
            server: s.clone(),
            ..Default::default()
        };
        let raw = s.trim();
        if raw.is_empty() {
            return out;
        }
        // Support `[v6]:port` and `host:port`.
        if let Some(rest) = raw.strip_prefix('[') {
            if let Some(end) = rest.find(']') {
                let host = &rest[..end];
                let tail = &rest[end + 1..];
                if let Some(port_str) = tail.strip_prefix(':') {
                    if let Ok(port) = port_str.parse::<u16>() {
                        out.server = host.to_string();
                        out.server_port = Some(port);
                    }
                }
                return out;
            }
        }
        if let Some((host, port_str)) = raw.rsplit_once(':') {
            if let Ok(port) = port_str.parse::<u16>() {
                if !host.is_empty() {
                    out.server = host.to_string();
                    out.server_port = Some(port);
                }
            }
        }
        out
    }
}

impl<'de> Deserialize<'de> for DerpMeshPeerIR {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        RawDerpMeshPeerIR::deserialize(deserializer).map(Into::into)
    }
}

/// Service type enumeration (Resolved, DERP, SSM, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ServiceType {
    /// systemd-resolved compatible DNS service
    #[default]
    Resolved,
    /// Shadowsocks Manager API service
    #[serde(rename = "ssm-api")]
    Ssmapi,
    /// Tailscale DERP relay service
    #[serde(rename = "derp")]
    Derp,
}

/// Service configuration IR.
#[derive(Debug, Clone, Serialize, PartialEq, Eq, Default)]
pub struct ServiceIR {
    /// Service type.
    #[serde(rename = "type")]
    pub ty: ServiceType,
    /// Unique tag identifier.
    #[serde(default)]
    pub tag: Option<String>,

    // Shared Listen Fields (Go parity: `option.ListenOptions`)
    // 公共监听字段（对齐 Go `option.ListenOptions`）
    /// Listen address.
    #[serde(default)]
    pub listen: Option<String>,
    /// Listen port.
    #[serde(default)]
    pub listen_port: Option<u16>,
    /// Bind interface.
    #[serde(default)]
    pub bind_interface: Option<String>,
    /// Routing mark.
    #[serde(default)]
    pub routing_mark: Option<u32>,
    /// Reuse address.
    #[serde(default)]
    pub reuse_addr: Option<bool>,
    /// Network namespace (Linux).
    #[serde(default)]
    pub netns: Option<String>,
    /// TCP fast open.
    #[serde(default)]
    pub tcp_fast_open: Option<bool>,
    /// TCP multipath.
    #[serde(default)]
    pub tcp_multi_path: Option<bool>,
    /// UDP fragmentation.
    #[serde(default)]
    pub udp_fragment: Option<bool>,
    /// UDP timeout (duration string, e.g. "5m").
    #[serde(default)]
    pub udp_timeout: Option<String>,
    /// Detour to another inbound tag (deprecated in Go; kept for parity).
    #[serde(default)]
    pub detour: Option<String>,

    // Deprecated inbound fields (Go parity; will be removed upstream)
    #[serde(default)]
    pub sniff: Option<bool>,
    #[serde(default)]
    pub sniff_override_destination: Option<bool>,
    #[serde(default)]
    pub sniff_timeout: Option<String>,
    #[serde(default)]
    pub domain_strategy: Option<String>,
    #[serde(default)]
    pub udp_disable_domain_unmapping: Option<bool>,

    // Shared TLS container (Go parity: `InboundTLSOptionsContainer`)
    #[serde(default)]
    pub tls: Option<InboundTlsOptionsIR>,

    // SSM API service fields (Go: `ssm-api`)
    /// Endpoint → managed Shadowsocks inbound tag mapping (Go: `servers`).
    #[serde(default)]
    pub servers: Option<std::collections::HashMap<String, String>>,
    /// Cache file path (Go: `cache_path`).
    #[serde(default)]
    pub cache_path: Option<String>,
    /// Authentication token for SSMAPI service (Go parity).
    #[serde(default)]
    pub auth_token: Option<String>,

    // DERP service fields
    /// DERP key/config file path (Go: `config_path`).
    #[serde(default)]
    pub config_path: Option<String>,
    /// Client verification endpoints (Go: `verify_client_endpoint`).
    #[serde(default)]
    pub verify_client_endpoint: Option<Listable<String>>,
    /// Client verification URLs (Go: `verify_client_url`).
    #[serde(default)]
    pub verify_client_url: Option<Listable<StringOrObj<DerpVerifyClientUrlIR>>>,
    /// Home page mode/url (Go: `home`).
    #[serde(default)]
    pub home: Option<String>,
    /// Mesh peer list (Go: `mesh_with`).
    #[serde(default)]
    pub mesh_with: Option<Listable<StringOrObj<DerpMeshPeerIR>>>,
    /// Mesh pre-shared key (Go: `mesh_psk`).
    #[serde(default)]
    pub mesh_psk: Option<String>,
    /// Mesh PSK file (Go: `mesh_psk_file`).
    #[serde(default)]
    pub mesh_psk_file: Option<String>,
    /// STUN server listen options (Go: `stun`).
    #[serde(default)]
    pub stun: Option<DerpStunOptionsIR>,
}

impl<'de> Deserialize<'de> for ServiceIR {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        super::raw::RawServiceIR::deserialize(deserializer).map(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn service_type_serialization() {
        // Test Resolved service
        let data = json!({
            "type": "resolved",
            "tag": "resolved-svc",
            "listen": "127.0.0.53",
            "listen_port": 53
        });
        let ir: ServiceIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.ty, ServiceType::Resolved);
        assert_eq!(ir.tag, Some("resolved-svc".to_string()));
        assert_eq!(ir.listen, Some("127.0.0.53".to_string()));
        assert_eq!(ir.listen_port, Some(53));

        let serialized = serde_json::to_value(&ir).unwrap();
        assert_eq!(serialized.get("type").unwrap(), "resolved");
    }

    #[test]
    fn ssmapi_service_serialization() {
        let data = json!({
            "type": "ssm-api",
            "tag": "ssm",
            "listen": "127.0.0.1",
            "listen_port": 6001,
            "servers": {
                "/": "ss-in"
            }
        });
        let ir: ServiceIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.ty, ServiceType::Ssmapi);
        assert_eq!(ir.tag, Some("ssm".to_string()));
        assert_eq!(ir.listen, Some("127.0.0.1".to_string()));
        assert_eq!(ir.listen_port, Some(6001));
        assert_eq!(
            ir.servers
                .as_ref()
                .and_then(|m| m.get("/"))
                .map(String::as_str),
            Some("ss-in")
        );

        let serialized = serde_json::to_value(&ir).unwrap();
        assert_eq!(serialized.get("type").unwrap(), "ssm-api");
    }

    #[test]
    fn derp_service_serialization() {
        let data = json!({
            "type": "derp",
            "tag": "derp-relay",
            "listen": "0.0.0.0",
            "listen_port": 3478,
            "config_path": "derper.key",
            "stun": {
                "enabled": true
            }
        });
        let ir: ServiceIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.ty, ServiceType::Derp);
        assert_eq!(ir.tag, Some("derp-relay".to_string()));
        assert_eq!(ir.listen, Some("0.0.0.0".to_string()));
        assert_eq!(ir.listen_port, Some(3478));
        assert_eq!(ir.config_path, Some("derper.key".to_string()));
        assert_eq!(ir.stun.as_ref().map(|s| s.enabled), Some(true));

        let serialized = serde_json::to_value(&ir).unwrap();
        assert_eq!(serialized.get("type").unwrap(), "derp");
    }

    #[test]
    fn derp_verify_client_url_listable_string_or_object() {
        // String shorthand.
        let data = json!({
            "type": "derp",
            "config_path": "derper.key",
            "tls": { "enabled": true, "certificate_path": "c.pem", "key_path": "k.pem" },
            "verify_client_url": "https://example.com/verify"
        });
        let ir: ServiceIR = serde_json::from_value(data).unwrap();
        let list = ir.verify_client_url.expect("verify_client_url");
        assert_eq!(list.items.len(), 1);
        assert_eq!(
            list.items[0].clone().into_inner().url,
            "https://example.com/verify"
        );

        // Object with Dial Fields flattened.
        let data = json!({
            "type": "derp",
            "config_path": "derper.key",
            "tls": { "enabled": true, "certificate_path": "c.pem", "key_path": "k.pem" },
            "verify_client_url": [
                "https://a/verify",
                { "url": "http://b/verify", "detour": "d1", "routing_mark": 123, "reuse_addr": true, "connect_timeout": "3s" }
            ]
        });
        let ir: ServiceIR = serde_json::from_value(data).unwrap();
        let list = ir.verify_client_url.expect("verify_client_url");
        assert_eq!(list.items.len(), 2);
        let a = list.items[0].clone().into_inner();
        assert_eq!(a.url, "https://a/verify");
        let b = list.items[1].clone().into_inner();
        assert_eq!(b.url, "http://b/verify");
        assert_eq!(b.dial.detour.as_deref(), Some("d1"));
        assert_eq!(b.dial.routing_mark, Some(123));
        assert_eq!(b.dial.reuse_addr, Some(true));
        assert_eq!(b.dial.connect_timeout.as_deref(), Some("3s"));
    }

    #[test]
    fn derp_mesh_with_string_or_object() {
        // String shorthand `host:port`.
        let data = json!({
            "type": "derp",
            "config_path": "derper.key",
            "tls": { "enabled": true, "certificate_path": "c.pem", "key_path": "k.pem" },
            "mesh_with": "peer.example.com:443"
        });
        let ir: ServiceIR = serde_json::from_value(data).unwrap();
        let mesh = ir.mesh_with.expect("mesh_with");
        assert_eq!(mesh.items.len(), 1);
        let p = mesh.items[0].clone().into_inner();
        assert_eq!(p.server, "peer.example.com");
        assert_eq!(p.server_port, Some(443));

        // Object form with TLS + Dial Fields.
        let data = json!({
            "type": "derp",
            "config_path": "derper.key",
            "tls": { "enabled": true, "certificate_path": "c.pem", "key_path": "k.pem" },
            "mesh_with": [
                {
                    "server": "10.0.0.2",
                    "server_port": 443,
                    "host": "derp.example.com",
                    "tls": { "enabled": true, "server_name": "derp.example.com", "insecure": true, "alpn": ["h2"] },
                    "detour": "d2"
                }
            ]
        });
        let ir: ServiceIR = serde_json::from_value(data).unwrap();
        let mesh = ir.mesh_with.expect("mesh_with");
        let p = mesh.items[0].clone().into_inner();
        assert_eq!(p.server, "10.0.0.2");
        assert_eq!(p.server_port, Some(443));
        assert_eq!(p.host.as_deref(), Some("derp.example.com"));
        let tls = p.tls.as_ref().expect("tls");
        assert!(tls.enabled);
        assert_eq!(tls.server_name.as_deref(), Some("derp.example.com"));
        assert_eq!(tls.insecure, Some(true));
        assert_eq!(tls.alpn.as_deref(), Some(&["h2".to_string()][..]));
        assert_eq!(p.dial.detour.as_deref(), Some("d2"));
    }

    #[test]
    fn derp_stun_bool_number_object() {
        let data = json!({
            "type": "derp",
            "config_path": "derper.key",
            "tls": { "enabled": true, "certificate_path": "c.pem", "key_path": "k.pem" },
            "stun": true
        });
        let ir: ServiceIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.stun.as_ref().map(|s| s.enabled), Some(true));
        assert_eq!(ir.stun.as_ref().and_then(|s| s.listen_port), None);

        let data = json!({
            "type": "derp",
            "config_path": "derper.key",
            "tls": { "enabled": true, "certificate_path": "c.pem", "key_path": "k.pem" },
            "stun": 3479
        });
        let ir: ServiceIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.stun.as_ref().map(|s| s.enabled), Some(true));
        assert_eq!(ir.stun.as_ref().and_then(|s| s.listen_port), Some(3479));

        let data = json!({
            "type": "derp",
            "config_path": "derper.key",
            "tls": { "enabled": true, "certificate_path": "c.pem", "key_path": "k.pem" },
            "stun": { "enabled": false, "listen": "::", "listen_port": 3478 }
        });
        let ir: ServiceIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.stun.as_ref().map(|s| s.enabled), Some(false));
        assert_eq!(
            ir.stun.as_ref().and_then(|s| s.listen.as_deref()),
            Some("::")
        );
        assert_eq!(ir.stun.as_ref().and_then(|s| s.listen_port), Some(3478));
    }

    #[test]
    fn derp_mesh_peer_from_string_parses_shorthand() {
        let peer = DerpMeshPeerIR::from("peer.example.com:443".to_string());
        assert_eq!(peer.server, "peer.example.com");
        assert_eq!(peer.server_port, Some(443));

        let ipv6 = DerpMeshPeerIR::from("[2001:db8::1]:8443".to_string());
        assert_eq!(ipv6.server, "2001:db8::1");
        assert_eq!(ipv6.server_port, Some(8443));
    }

    #[test]
    fn derp_verify_client_url_from_string_parses_shorthand() {
        let verify = DerpVerifyClientUrlIR::from("https://example.com/verify".to_string());
        assert_eq!(verify.url, "https://example.com/verify");
        assert_eq!(verify.dial, DerpDialOptionsIR::default());
    }

    #[test]
    fn wp30ag_pin_service_derp_owner_is_service_rs() {
        let source = include_str!("service.rs");
        for needle in [
            "pub struct InboundTlsOptionsIR",
            "pub struct DerpStunOptionsIR",
            "pub struct DerpDomainResolverIR",
            "pub struct DerpDialOptionsIR",
            "pub struct DerpVerifyClientUrlIR",
            "pub struct DerpOutboundTlsOptionsIR",
            "pub struct DerpMeshPeerIR",
        ] {
            assert!(
                source.contains(needle),
                "expected `{needle}` to live in ir/service.rs"
            );
        }
    }

    #[test]
    fn wp30ag_pin_mod_rs_only_reexports_service_derp_types() {
        let source = include_str!("mod.rs");
        assert!(
            source.contains("pub use service::{")
                && source.contains("DerpDialOptionsIR")
                && source.contains("DerpMeshPeerIR")
                && source.contains("InboundTlsOptionsIR"),
            "expected ir/mod.rs to re-export service/DERP types"
        );
        for needle in [
            "pub struct InboundTlsOptionsIR",
            "pub struct DerpStunOptionsIR",
            "pub struct DerpDomainResolverIR",
            "pub struct DerpDialOptionsIR",
            "pub struct DerpVerifyClientUrlIR",
            "pub struct DerpOutboundTlsOptionsIR",
            "pub struct DerpMeshPeerIR",
        ] {
            assert!(
                !source.contains(needle),
                "expected ir/mod.rs to stop owning `{needle}`"
            );
        }
    }
}
