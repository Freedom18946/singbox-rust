use super::FirstPassConcreteOutbound;
use sb_config::ir::{MultiplexOptionsIR, OutboundIR};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ShadowsocksCipherSpec {
    Aes256Gcm,
    Chacha20Poly1305,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ShadowsocksSpec {
    pub server: String,
    pub port: u16,
    pub password: String,
    pub cipher: ShadowsocksCipherSpec,
    pub multiplex: Option<MultiplexOptionsIR>,
}

pub(crate) fn build_shadowsocks_outbound(
    outbound_name: &str,
    outbound: &OutboundIR,
) -> Option<ShadowsocksSpec> {
    let Some(server) = outbound.server.as_ref() else {
        tracing::warn!(outbound = %outbound_name, "shadowsocks requires server");
        return None;
    };
    let Some(port) = outbound.port else {
        tracing::warn!(outbound = %outbound_name, "shadowsocks requires port");
        return None;
    };
    let password = match &outbound.password {
        Some(password) if !password.is_empty() => password.clone(),
        _ => {
            tracing::warn!(outbound = %outbound_name, "shadowsocks requires password");
            return None;
        }
    };

    let method = outbound
        .method
        .as_deref()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    let cipher = match method.as_str() {
        "aes-256-gcm" => ShadowsocksCipherSpec::Aes256Gcm,
        "chacha20-poly1305" => ShadowsocksCipherSpec::Chacha20Poly1305,
        "" => {
            tracing::warn!(outbound = %outbound_name, "shadowsocks requires method");
            return None;
        }
        other => {
            tracing::warn!(
                outbound = %outbound_name,
                method = %other,
                "unsupported shadowsocks method"
            );
            return None;
        }
    };

    Some(ShadowsocksSpec {
        server: server.clone(),
        port,
        password,
        cipher,
        multiplex: outbound
            .multiplex
            .clone()
            .filter(|multiplex| multiplex.enabled),
    })
}

impl From<ShadowsocksSpec> for FirstPassConcreteOutbound {
    fn from(value: ShadowsocksSpec) -> Self {
        Self::Shadowsocks(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_config::ir::{BrutalIR, OutboundType};

    #[test]
    fn shadowsocks_builder_preserves_method_transport_and_multiplex_shape() {
        let outbound = OutboundIR {
            ty: OutboundType::Shadowsocks,
            name: Some("ss".to_string()),
            server: Some("127.0.0.1".to_string()),
            port: Some(8388),
            password: Some("secret".to_string()),
            method: Some("ChaCha20-Poly1305".to_string()),
            multiplex: Some(MultiplexOptionsIR {
                enabled: true,
                protocol: Some("yamux".to_string()),
                max_connections: Some(2),
                brutal: Some(BrutalIR { up: 10, down: 20 }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let built = build_shadowsocks_outbound("ss", &outbound).expect("shadowsocks config");
        assert_eq!(built.server, "127.0.0.1");
        assert_eq!(built.port, 8388);
        assert_eq!(built.password, "secret");
        assert_eq!(built.cipher, ShadowsocksCipherSpec::Chacha20Poly1305);
        let multiplex = built.multiplex.expect("multiplex config");
        assert!(multiplex.enabled);
        assert_eq!(multiplex.protocol.as_deref(), Some("yamux"));
        assert_eq!(multiplex.max_connections, Some(2));
        assert_eq!(multiplex.brutal, Some(BrutalIR { up: 10, down: 20 }));
    }

    #[test]
    fn shadowsocks_builder_rejects_missing_or_unsupported_cipher() {
        let missing = build_shadowsocks_outbound(
            "ss",
            &OutboundIR {
                ty: OutboundType::Shadowsocks,
                name: Some("ss".to_string()),
                server: Some("127.0.0.1".to_string()),
                port: Some(8388),
                password: Some("secret".to_string()),
                ..Default::default()
            },
        );
        assert!(missing.is_none());

        let unsupported = build_shadowsocks_outbound(
            "ss",
            &OutboundIR {
                ty: OutboundType::Shadowsocks,
                name: Some("ss".to_string()),
                server: Some("127.0.0.1".to_string()),
                port: Some(8388),
                password: Some("secret".to_string()),
                method: Some("rc4-md5".to_string()),
                ..Default::default()
            },
        );
        assert!(unsupported.is_none());
    }
}
