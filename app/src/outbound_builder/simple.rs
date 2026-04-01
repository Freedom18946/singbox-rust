use super::FirstPassConcreteOutbound;
use sb_config::ir::{OutboundIR, OutboundType};
use std::net::SocketAddr;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum SimpleOutboundSpec {
    Socks(SocksProxySpec),
    Http(HttpProxySpec),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SocksProxySpec {
    pub proxy_addr: SocketAddr,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HttpProxySpec {
    pub proxy_addr: SocketAddr,
    pub username: Option<String>,
    pub password: Option<String>,
}

pub(crate) fn build_simple_outbound(outbound: &OutboundIR) -> Option<SimpleOutboundSpec> {
    let host = outbound.server.as_deref()?;
    let port = outbound.port?;
    let proxy_addr = super::resolve_host_port(host, port)?;
    let username = outbound
        .credentials
        .as_ref()
        .and_then(|credentials| credentials.username.clone());
    let password = outbound
        .credentials
        .as_ref()
        .and_then(|credentials| credentials.password.clone());

    match outbound.ty {
        OutboundType::Socks => Some(SimpleOutboundSpec::Socks(SocksProxySpec {
            proxy_addr,
            username,
            password,
        })),
        OutboundType::Http => Some(SimpleOutboundSpec::Http(HttpProxySpec {
            proxy_addr,
            username,
            password,
        })),
        _ => None,
    }
}

impl From<SimpleOutboundSpec> for FirstPassConcreteOutbound {
    fn from(value: SimpleOutboundSpec) -> Self {
        match value {
            SimpleOutboundSpec::Socks(spec) => Self::Socks(spec),
            SimpleOutboundSpec::Http(spec) => Self::Http(spec),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_config::ir::{Credentials, OutboundIR};

    #[test]
    fn simple_proxy_family_covers_direct_block_socks_and_http_paths() {
        assert!(matches!(
            FirstPassConcreteOutbound::Direct,
            FirstPassConcreteOutbound::Direct
        ));
        assert!(matches!(
            FirstPassConcreteOutbound::Block,
            FirstPassConcreteOutbound::Block
        ));

        let socks = build_simple_outbound(&OutboundIR {
            ty: OutboundType::Socks,
            server: Some("127.0.0.1".to_string()),
            port: Some(1080),
            credentials: Some(Credentials {
                username: Some("alice".to_string()),
                password: Some("secret".to_string()),
                username_env: None,
                password_env: None,
            }),
            ..Default::default()
        })
        .expect("socks outbound");
        let SimpleOutboundSpec::Socks(socks) = socks else {
            panic!("expected socks variant");
        };
        assert_eq!(socks.proxy_addr.port(), 1080);
        assert_eq!(socks.username.as_deref(), Some("alice"));
        assert_eq!(socks.password.as_deref(), Some("secret"));

        let http = build_simple_outbound(&OutboundIR {
            ty: OutboundType::Http,
            server: Some("127.0.0.1".to_string()),
            port: Some(8080),
            ..Default::default()
        })
        .expect("http outbound");
        let SimpleOutboundSpec::Http(http) = http else {
            panic!("expected http variant");
        };
        assert_eq!(http.proxy_addr.port(), 8080);
        assert_eq!(http.username, None);
        assert_eq!(http.password, None);
    }

    #[test]
    fn simple_proxy_family_skips_unresolvable_host_or_missing_endpoint() {
        let unresolved = build_simple_outbound(&OutboundIR {
            ty: OutboundType::Socks,
            server: Some("invalid.invalid.invalid".to_string()),
            port: Some(1080),
            ..Default::default()
        });
        assert!(unresolved.is_none());

        let missing = build_simple_outbound(&OutboundIR {
            ty: OutboundType::Http,
            server: Some("127.0.0.1".to_string()),
            ..Default::default()
        });
        assert!(missing.is_none());
    }
}
