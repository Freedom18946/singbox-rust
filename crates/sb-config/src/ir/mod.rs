//! Strongly-typed intermediate representation (IR) for config and routing rules.
//! 配置和路由规则的强类型中间表示 (IR)。
//!
//! Both V1 and V2 formats are converted to IR, which is then consumed by routing
//! and adapter layers. Field naming aligns with Go sing-box; new fields extend
//! without changing default behavior.
//! V1 和 V2 格式都会被转换为 IR，然后由路由和适配器层消费。
//! 字段命名与 Go sing-box 保持一致；新字段的扩展不会改变默认行为。

mod credentials;
pub mod diff;
mod dns;
pub(crate) mod dns_raw;
mod endpoint;
mod inbound;
pub(crate) mod minimize;
mod multiplex;
pub(crate) mod normalize;
mod outbound;
pub(crate) mod planned;
mod raw;
mod route;
mod service;
mod validated;
mod value_wrappers;

pub use credentials::Credentials;
pub use dns::{DnsHostIR, DnsIR, DnsRuleIR, DnsServerIR};
pub use endpoint::{EndpointIR, EndpointType, WireGuardPeerIR};
pub use inbound::{
    AnyTlsUserIR, Hysteria2UserIR, HysteriaUserIR, InboundIR, InboundType, MasqueradeFileIR,
    MasqueradeIR, MasqueradeProxyIR, MasqueradeStringIR, ShadowTlsHandshakeIR, ShadowTlsUserIR,
    ShadowsocksUserIR, TrojanUserIR, TuicUserIR, TunOptionsIR, VlessUserIR, VmessUserIR,
};
pub use multiplex::{BrutalIR, MultiplexOptionsIR};
pub use outbound::{HeaderEntry, OutboundIR, OutboundType};
pub use raw::{
    RawAnyTlsUserIR, RawBrutalIR, RawCertificateIR, RawConfigRoot, RawCredentials,
    RawDerpDialOptionsIR, RawDerpDomainResolverIR, RawDerpMeshPeerIR, RawDerpOutboundTlsOptionsIR,
    RawDerpStunOptionsIR, RawDerpStunOptionsObj, RawDerpVerifyClientUrlIR, RawDnsHostIR, RawDnsIR,
    RawDnsRuleIR, RawDnsServerIR, RawDomainResolveOptionsIR, RawEndpointIR, RawHeaderEntry,
    RawHysteria2UserIR, RawHysteriaUserIR, RawInboundIR, RawInboundTlsOptionsIR, RawLogIR,
    RawMasqueradeFileIR, RawMasqueradeIR, RawMasqueradeProxyIR, RawMasqueradeStringIR,
    RawMultiplexOptionsIR, RawNtpIR, RawOutboundIR, RawRouteIR, RawRuleIR, RawRuleSetIR,
    RawServiceIR, RawShadowTlsHandshakeIR, RawShadowTlsUserIR, RawShadowsocksUserIR,
    RawTrojanUserIR, RawTuicUserIR, RawTunOptionsIR, RawVlessUserIR, RawVmessUserIR,
    RawWireGuardPeerIR,
};
pub use route::{DomainResolveOptionsIR, RouteIR, RuleAction, RuleIR, RuleSetIR};
pub use service::{
    DerpDialOptionsIR, DerpDomainResolverIR, DerpMeshPeerIR, DerpOutboundTlsOptionsIR,
    DerpStunOptionsIR, DerpVerifyClientUrlIR, InboundTlsOptionsIR, ServiceIR, ServiceType,
};
pub use validated::{CertificateIR, ConfigIR, LogIR, NtpIR};
pub use value_wrappers::{Listable, StringOrObj};

pub mod experimental;
pub use experimental::*;

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn inbound_type_serialization() {
        let data = json!({
            "ty": "naive",
            "listen": "127.0.0.1",
            "port": 1080usize
        });
        let ir: InboundIR = serde_json::from_value(data).unwrap();
        assert_eq!(ir.ty, InboundType::Naive);

        let serialized = serde_json::to_value(&ir).unwrap();
        assert_eq!(serialized.get("ty").unwrap(), "naive");
    }

    #[test]
    fn inbound_ir_deserializes_shadowtls_runtime_fields() {
        let inbound: InboundIR = serde_json::from_value(json!({
            "ty": "shadowtls",
            "listen": "127.0.0.1",
            "port": 443,
            "detour": "ss-detour",
            "version": 3,
            "users_shadowtls": [
                { "name": "alice", "password": "pw1" }
            ],
            "shadowtls_handshake": {
                "server": "handshake.example.com",
                "server_port": 443
            },
            "shadowtls_handshake_for_server_name": {
                "cdn.example.com": {
                    "server": "cdn-handshake.example.com",
                    "server_port": 8443
                }
            },
            "shadowtls_strict_mode": true,
            "shadowtls_wildcard_sni": "authed"
        }))
        .unwrap();

        assert_eq!(inbound.detour.as_deref(), Some("ss-detour"));
        assert_eq!(inbound.version, Some(3));
        assert_eq!(
            inbound
                .users_shadowtls
                .as_ref()
                .expect("shadowtls users should deserialize")[0]
                .name,
            "alice"
        );
        assert_eq!(
            inbound
                .shadowtls_handshake
                .as_ref()
                .expect("handshake should deserialize")
                .server,
            "handshake.example.com"
        );
        assert_eq!(
            inbound
                .shadowtls_handshake_for_server_name
                .as_ref()
                .and_then(|m| m.get("cdn.example.com"))
                .expect("handshake override should deserialize")
                .server_port,
            8443
        );
        assert_eq!(inbound.shadowtls_strict_mode, Some(true));
        assert_eq!(inbound.shadowtls_wildcard_sni.as_deref(), Some("authed"));
    }
}
