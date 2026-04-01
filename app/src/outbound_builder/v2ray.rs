use super::FirstPassConcreteOutbound;
use sb_config::ir::{MultiplexOptionsIR, OutboundIR, OutboundType};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum V2RayOutboundSpec {
    Vless(VlessSpec),
    Vmess(VmessSpec),
    Trojan(TrojanSpec),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VlessSpec {
    pub server: String,
    pub port: u16,
    pub uuid: uuid::Uuid,
    pub flow: Option<String>,
    pub encryption: Option<String>,
    pub transport: Option<Vec<String>>,
    pub ws_path: Option<String>,
    pub ws_host: Option<String>,
    pub h2_path: Option<String>,
    pub h2_host: Option<String>,
    pub tls_sni: Option<String>,
    pub tls_alpn: Option<Vec<String>>,
    pub utls_fingerprint: Option<String>,
    pub grpc_service: Option<String>,
    pub grpc_method: Option<String>,
    pub grpc_authority: Option<String>,
    pub grpc_metadata: Vec<(String, String)>,
    pub http_upgrade_path: Option<String>,
    pub http_upgrade_headers: Vec<(String, String)>,
    pub multiplex: Option<MultiplexOptionsIR>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VmessSpec {
    pub server: String,
    pub port: u16,
    pub id: uuid::Uuid,
    pub security: String,
    pub alter_id: u8,
    pub transport: Option<Vec<String>>,
    pub ws_path: Option<String>,
    pub ws_host: Option<String>,
    pub h2_path: Option<String>,
    pub h2_host: Option<String>,
    pub tls_sni: Option<String>,
    pub tls_alpn: Option<Vec<String>>,
    pub utls_fingerprint: Option<String>,
    pub grpc_service: Option<String>,
    pub grpc_method: Option<String>,
    pub grpc_authority: Option<String>,
    pub grpc_metadata: Vec<(String, String)>,
    pub http_upgrade_path: Option<String>,
    pub http_upgrade_headers: Vec<(String, String)>,
    pub multiplex: Option<MultiplexOptionsIR>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TrojanSpec {
    pub server: String,
    pub port: u16,
    pub password: String,
    pub sni: String,
    pub alpn: Option<Vec<String>>,
    pub skip_cert_verify: bool,
}

pub(crate) fn build_v2ray_outbound(
    _outbound_name: &str,
    outbound: &OutboundIR,
) -> Option<V2RayOutboundSpec> {
    match outbound.ty {
        OutboundType::Vless => build_vless_outbound(outbound),
        OutboundType::Vmess => build_vmess_outbound(outbound),
        OutboundType::Trojan => build_trojan_outbound(outbound),
        _ => None,
    }
}

fn build_vless_outbound(outbound: &OutboundIR) -> Option<V2RayOutboundSpec> {
    let (Some(server), Some(port), Some(uuid_str)) = (
        outbound.server.as_ref(),
        outbound.port,
        outbound.uuid.as_ref(),
    ) else {
        return None;
    };
    let Ok(uuid) = uuid::Uuid::parse_str(uuid_str) else {
        return None;
    };

    Some(V2RayOutboundSpec::Vless(VlessSpec {
        server: server.clone(),
        port,
        uuid,
        flow: outbound.flow.clone(),
        encryption: Some("none".to_string()),
        transport: outbound.transport.clone(),
        ws_path: outbound.ws_path.clone(),
        ws_host: outbound.ws_host.clone(),
        h2_path: outbound.h2_path.clone(),
        h2_host: outbound.h2_host.clone(),
        tls_sni: outbound.tls_sni.clone(),
        tls_alpn: super::shared_alpn_tokens(outbound),
        utls_fingerprint: outbound.utls_fingerprint.clone(),
        grpc_service: outbound.grpc_service.clone(),
        grpc_method: outbound.grpc_method.clone(),
        grpc_authority: outbound.grpc_authority.clone(),
        grpc_metadata: super::map_header_entries(&outbound.grpc_metadata),
        http_upgrade_path: outbound.http_upgrade_path.clone(),
        http_upgrade_headers: super::map_header_entries(&outbound.http_upgrade_headers),
        multiplex: outbound.multiplex.clone(),
    }))
}

fn build_vmess_outbound(outbound: &OutboundIR) -> Option<V2RayOutboundSpec> {
    let (Some(server), Some(port), Some(id_str)) = (
        outbound.server.as_ref(),
        outbound.port,
        outbound.uuid.as_ref(),
    ) else {
        return None;
    };
    let Ok(id) = uuid::Uuid::parse_str(id_str) else {
        return None;
    };

    Some(V2RayOutboundSpec::Vmess(VmessSpec {
        server: server.clone(),
        port,
        id,
        security: "aes-128-gcm".to_string(),
        alter_id: 0,
        transport: outbound.transport.clone(),
        ws_path: outbound.ws_path.clone(),
        ws_host: outbound.ws_host.clone(),
        h2_path: outbound.h2_path.clone(),
        h2_host: outbound.h2_host.clone(),
        tls_sni: outbound.tls_sni.clone(),
        tls_alpn: super::shared_alpn_tokens(outbound),
        utls_fingerprint: outbound.utls_fingerprint.clone(),
        grpc_service: outbound.grpc_service.clone(),
        grpc_method: outbound.grpc_method.clone(),
        grpc_authority: outbound.grpc_authority.clone(),
        grpc_metadata: super::map_header_entries(&outbound.grpc_metadata),
        http_upgrade_path: outbound.http_upgrade_path.clone(),
        http_upgrade_headers: super::map_header_entries(&outbound.http_upgrade_headers),
        multiplex: outbound.multiplex.clone(),
    }))
}

fn build_trojan_outbound(outbound: &OutboundIR) -> Option<V2RayOutboundSpec> {
    let (Some(server), Some(port), Some(password)) = (
        outbound.server.as_ref(),
        outbound.port,
        outbound.password.as_ref(),
    ) else {
        return None;
    };

    let alpn = super::shared_alpn_tokens(outbound).filter(|items| !items.is_empty());

    Some(V2RayOutboundSpec::Trojan(TrojanSpec {
        server: server.clone(),
        port,
        password: password.clone(),
        sni: outbound.tls_sni.clone().unwrap_or_else(|| server.clone()),
        alpn,
        skip_cert_verify: outbound.skip_cert_verify.unwrap_or(false),
    }))
}

impl From<V2RayOutboundSpec> for FirstPassConcreteOutbound {
    fn from(value: V2RayOutboundSpec) -> Self {
        match value {
            V2RayOutboundSpec::Vless(spec) => Self::Vless(spec),
            V2RayOutboundSpec::Vmess(spec) => Self::Vmess(spec),
            V2RayOutboundSpec::Trojan(spec) => Self::Trojan(spec),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_config::ir::{HeaderEntry, OutboundType};

    #[test]
    fn trojan_builder_preserves_tls_overrides() {
        let outbound = OutboundIR {
            ty: OutboundType::Trojan,
            name: Some("trojan".to_string()),
            server: Some("trojan.example.com".to_string()),
            port: Some(443),
            password: Some("s3cret".to_string()),
            tls_sni: Some("auth.example.com".to_string()),
            alpn: Some("h2, http/1.1".to_string()),
            skip_cert_verify: Some(true),
            ..Default::default()
        };

        let built = build_v2ray_outbound("trojan", &outbound).expect("trojan config");
        let V2RayOutboundSpec::Trojan(built) = built else {
            panic!("expected trojan variant");
        };

        assert_eq!(built.sni, "auth.example.com");
        assert!(built.skip_cert_verify);
        assert_eq!(
            built.alpn,
            Some(vec!["h2".to_string(), "http/1.1".to_string()])
        );
    }

    #[test]
    fn vless_builder_preserves_transport_headers_and_multiplex() {
        let outbound = OutboundIR {
            ty: OutboundType::Vless,
            name: Some("vless".to_string()),
            server: Some("vless.example.com".to_string()),
            port: Some(443),
            uuid: Some("12345678-1234-1234-1234-123456789abc".to_string()),
            transport: Some(vec!["grpc".to_string(), "httpupgrade".to_string()]),
            grpc_service: Some("TunnelService".to_string()),
            grpc_method: Some("Tunnel".to_string()),
            grpc_authority: Some("grpc.example.com".to_string()),
            grpc_metadata: vec![
                HeaderEntry {
                    key: "auth".to_string(),
                    value: "token".to_string(),
                },
                HeaderEntry {
                    key: "foo".to_string(),
                    value: "bar".to_string(),
                },
            ],
            http_upgrade_path: Some("/upgrade".to_string()),
            http_upgrade_headers: vec![HeaderEntry {
                key: "Authorization".to_string(),
                value: "Bearer token".to_string(),
            }],
            multiplex: Some(MultiplexOptionsIR {
                enabled: true,
                protocol: Some("yamux".to_string()),
                ..Default::default()
            }),
            ..Default::default()
        };

        let built = build_v2ray_outbound("vless", &outbound).expect("vless config");
        let V2RayOutboundSpec::Vless(built) = built else {
            panic!("expected vless variant");
        };

        assert_eq!(built.server, "vless.example.com");
        assert_eq!(built.port, 443);
        assert_eq!(
            built.transport,
            Some(vec!["grpc".to_string(), "httpupgrade".to_string()])
        );
        assert_eq!(built.grpc_service.as_deref(), Some("TunnelService"));
        assert_eq!(built.grpc_method.as_deref(), Some("Tunnel"));
        assert_eq!(built.grpc_authority.as_deref(), Some("grpc.example.com"));
        assert!(built
            .grpc_metadata
            .contains(&("auth".to_string(), "token".to_string())));
        assert!(built
            .grpc_metadata
            .contains(&("foo".to_string(), "bar".to_string())));
        assert_eq!(built.http_upgrade_path.as_deref(), Some("/upgrade"));
        assert!(built
            .http_upgrade_headers
            .contains(&("Authorization".to_string(), "Bearer token".to_string())));
        assert_eq!(
            built.multiplex,
            Some(MultiplexOptionsIR {
                enabled: true,
                protocol: Some("yamux".to_string()),
                ..Default::default()
            })
        );
    }

    #[test]
    fn vmess_builder_uses_legacy_defaults_and_tls_tokens() {
        let outbound = OutboundIR {
            ty: OutboundType::Vmess,
            name: Some("vmess".to_string()),
            server: Some("vmess.example.com".to_string()),
            port: Some(443),
            uuid: Some("12345678-1234-1234-1234-123456789abc".to_string()),
            alpn: Some("h2, http/1.1".to_string()),
            ..Default::default()
        };

        let built = build_v2ray_outbound("vmess", &outbound).expect("vmess config");
        let V2RayOutboundSpec::Vmess(built) = built else {
            panic!("expected vmess variant");
        };

        assert_eq!(built.server, "vmess.example.com");
        assert_eq!(built.port, 443);
        assert_eq!(built.security, "aes-128-gcm");
        assert_eq!(built.alter_id, 0);
        assert_eq!(
            built.tls_alpn,
            Some(vec!["h2".to_string(), "http/1.1".to_string()])
        );
    }
}
