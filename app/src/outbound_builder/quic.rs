use super::FirstPassConcreteOutbound;
use sb_config::ir::{OutboundIR, OutboundType};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum QuicOutboundSpec {
    Hysteria2(Hysteria2Spec),
    Tuic(TuicSpec),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BrutalSpec {
    pub up_mbps: u32,
    pub down_mbps: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Hysteria2Spec {
    pub server: String,
    pub port: u16,
    pub password: String,
    pub congestion_control: Option<String>,
    pub up_mbps: Option<u32>,
    pub down_mbps: Option<u32>,
    pub obfs: Option<String>,
    pub skip_cert_verify: bool,
    pub sni: Option<String>,
    pub alpn: Option<Vec<String>>,
    pub salamander: Option<String>,
    pub brutal: Option<BrutalSpec>,
    pub tls_ca_paths: Vec<String>,
    pub tls_ca_pem: Vec<String>,
    pub zero_rtt_handshake: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum UdpRelayModeSpec {
    Native,
    Quic,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TuicSpec {
    pub server: String,
    pub port: u16,
    pub uuid: uuid::Uuid,
    pub token: String,
    pub password: Option<String>,
    pub congestion_control: Option<String>,
    pub alpn: Option<Vec<String>>,
    pub skip_cert_verify: bool,
    pub sni: Option<String>,
    pub tls_ca_paths: Vec<String>,
    pub tls_ca_pem: Vec<String>,
    pub udp_relay_mode: UdpRelayModeSpec,
    pub udp_over_stream: bool,
    pub zero_rtt_handshake: bool,
}

pub(crate) fn build_quic_outbound(
    outbound_name: &str,
    outbound: &OutboundIR,
) -> Option<QuicOutboundSpec> {
    match outbound.ty {
        OutboundType::Hysteria2 => build_hysteria2_outbound(outbound_name, outbound),
        OutboundType::Tuic => build_tuic_outbound(outbound_name, outbound),
        _ => None,
    }
}

fn build_hysteria2_outbound(
    outbound_name: &str,
    outbound: &OutboundIR,
) -> Option<QuicOutboundSpec> {
    let (Some(server), Some(port), Some(password)) = (
        outbound.server.as_ref(),
        outbound.port,
        outbound.password.as_ref(),
    ) else {
        return None;
    };

    let brutal = match (outbound.brutal_up_mbps, outbound.brutal_down_mbps) {
        (Some(up_mbps), Some(down_mbps)) => Some(BrutalSpec { up_mbps, down_mbps }),
        (Some(_), None) | (None, Some(_)) => {
            tracing::warn!(
                outbound = %outbound_name,
                "ignored partial brutal config; both up_mbps/down_mbps required"
            );
            None
        }
        _ => None,
    };

    Some(QuicOutboundSpec::Hysteria2(Hysteria2Spec {
        server: server.clone(),
        port,
        password: password.clone(),
        congestion_control: outbound.congestion_control.clone(),
        up_mbps: outbound.up_mbps,
        down_mbps: outbound.down_mbps,
        obfs: outbound.obfs.clone(),
        skip_cert_verify: outbound.skip_cert_verify.unwrap_or(false),
        sni: outbound.tls_sni.clone(),
        alpn: super::shared_alpn_tokens(outbound),
        salamander: outbound.salamander.clone(),
        brutal,
        tls_ca_paths: Vec::new(),
        tls_ca_pem: Vec::new(),
        zero_rtt_handshake: false,
    }))
}

fn build_tuic_outbound(outbound_name: &str, outbound: &OutboundIR) -> Option<QuicOutboundSpec> {
    let (Some(server), Some(port), Some(uuid_str), Some(token)) = (
        outbound.server.as_ref(),
        outbound.port,
        outbound.uuid.as_ref(),
        outbound.token.as_ref(),
    ) else {
        tracing::warn!(
            outbound = %outbound_name,
            "tuic outbound requires server, port, uuid, and token"
        );
        return None;
    };

    let uuid = match uuid::Uuid::parse_str(uuid_str) {
        Ok(uuid) => uuid,
        Err(error) => {
            tracing::warn!(
                outbound = %outbound_name,
                error = %error,
                "invalid UUID for TUIC outbound"
            );
            return None;
        }
    };

    let udp_relay_mode = match outbound.udp_relay_mode.as_deref() {
        Some(mode) if mode.eq_ignore_ascii_case("quic") => UdpRelayModeSpec::Quic,
        _ => UdpRelayModeSpec::Native,
    };

    Some(QuicOutboundSpec::Tuic(TuicSpec {
        server: server.clone(),
        port,
        uuid,
        token: token.clone(),
        password: outbound.password.clone(),
        congestion_control: outbound.congestion_control.clone(),
        alpn: super::shared_alpn_tokens(outbound),
        skip_cert_verify: outbound.skip_cert_verify.unwrap_or(false),
        sni: outbound.tls_sni.clone(),
        tls_ca_paths: Vec::new(),
        tls_ca_pem: Vec::new(),
        udp_relay_mode,
        udp_over_stream: outbound.udp_over_stream.unwrap_or(false),
        zero_rtt_handshake: outbound.zero_rtt_handshake.unwrap_or(false),
    }))
}

impl From<QuicOutboundSpec> for FirstPassConcreteOutbound {
    fn from(value: QuicOutboundSpec) -> Self {
        match value {
            QuicOutboundSpec::Hysteria2(spec) => Self::Hysteria2(spec),
            QuicOutboundSpec::Tuic(spec) => Self::Tuic(spec),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hysteria2_builder_preserves_runtime_config_and_brutal_alpn_behavior() {
        let outbound = OutboundIR {
            ty: OutboundType::Hysteria2,
            name: Some("hy2".to_string()),
            server: Some("hy2.example.com".to_string()),
            port: Some(443),
            password: Some("secret".to_string()),
            congestion_control: Some("brutal".to_string()),
            up_mbps: Some(150),
            down_mbps: Some(200),
            obfs: Some("obfs-key".to_string()),
            salamander: Some("fingerprint".to_string()),
            alpn: Some("h3, hysteria2".to_string()),
            brutal_up_mbps: Some(300),
            brutal_down_mbps: Some(400),
            ..Default::default()
        };

        let built = build_quic_outbound("hy2", &outbound).expect("hysteria2 config");
        let QuicOutboundSpec::Hysteria2(built) = built else {
            panic!("expected hysteria2 variant");
        };

        assert_eq!(built.server, "hy2.example.com");
        assert_eq!(built.port, 443);
        assert_eq!(built.password, "secret");
        assert_eq!(built.congestion_control.as_deref(), Some("brutal"));
        assert_eq!(built.up_mbps, Some(150));
        assert_eq!(built.down_mbps, Some(200));
        assert_eq!(
            built.alpn,
            Some(vec!["h3".to_string(), "hysteria2".to_string()])
        );
        assert_eq!(
            built.brutal,
            Some(BrutalSpec {
                up_mbps: 300,
                down_mbps: 400
            })
        );
        assert!(!built.zero_rtt_handshake);
    }

    #[test]
    fn hysteria2_builder_ignores_partial_brutal_config() {
        let outbound = OutboundIR {
            ty: OutboundType::Hysteria2,
            name: Some("hy2".to_string()),
            server: Some("hy2.example.com".to_string()),
            port: Some(443),
            password: Some("secret".to_string()),
            brutal_up_mbps: Some(300),
            ..Default::default()
        };

        let built = build_quic_outbound("hy2", &outbound).expect("hysteria2 config");
        let QuicOutboundSpec::Hysteria2(built) = built else {
            panic!("expected hysteria2 variant");
        };
        assert_eq!(built.brutal, None);
    }

    #[test]
    fn tuic_builder_preserves_relay_mode_and_zero_rtt() {
        let outbound = OutboundIR {
            ty: OutboundType::Tuic,
            name: Some("tuic".to_string()),
            server: Some("tuic.example.com".to_string()),
            port: Some(443),
            uuid: Some("12345678-1234-1234-1234-123456789abc".to_string()),
            token: Some("secret-token".to_string()),
            password: Some("optional-pass".to_string()),
            congestion_control: Some("bbr".to_string()),
            alpn: Some("h3".to_string()),
            skip_cert_verify: Some(true),
            udp_relay_mode: Some("quic".to_string()),
            udp_over_stream: Some(true),
            zero_rtt_handshake: Some(true),
            ..Default::default()
        };

        let built = build_quic_outbound("tuic", &outbound).expect("tuic config");
        let QuicOutboundSpec::Tuic(built) = built else {
            panic!("expected tuic variant");
        };

        assert_eq!(built.server, "tuic.example.com");
        assert_eq!(built.port, 443);
        assert_eq!(built.token, "secret-token");
        assert_eq!(built.password.as_deref(), Some("optional-pass"));
        assert_eq!(built.congestion_control.as_deref(), Some("bbr"));
        assert_eq!(built.alpn, Some(vec!["h3".to_string()]));
        assert!(built.skip_cert_verify);
        assert!(matches!(built.udp_relay_mode, UdpRelayModeSpec::Quic));
        assert!(built.udp_over_stream);
        assert!(built.zero_rtt_handshake);
    }

    #[test]
    fn tuic_builder_rejects_invalid_uuid() {
        let outbound = OutboundIR {
            ty: OutboundType::Tuic,
            name: Some("tuic".to_string()),
            server: Some("tuic.example.com".to_string()),
            port: Some(443),
            uuid: Some("not-a-uuid".to_string()),
            token: Some("secret-token".to_string()),
            ..Default::default()
        };

        assert!(build_quic_outbound("tuic", &outbound).is_none());
    }
}
