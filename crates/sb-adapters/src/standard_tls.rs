//! Typed IR-to-runtime lowering for standard TLS.

#[cfg(feature = "transport_tls")]
use sb_config::ir::{InboundIR, OutboundIR};
#[cfg(feature = "transport_tls")]
use sb_transport::{StandardTlsConfig, TlsConfig, TlsVersion};

#[cfg(feature = "transport_tls")]
fn parse_version(value: Option<&str>, context: &str) -> Result<Option<TlsVersion>, String> {
    value
        .map(|value| match value {
            "1.2" => Ok(TlsVersion::V1_2),
            "1.3" => Ok(TlsVersion::V1_3),
            _ => Err(format!(
                "{context}: unsupported TLS version {value:?}; expected 1.2 or 1.3"
            )),
        })
        .transpose()
}

#[cfg(feature = "transport_tls")]
fn joined_pem(lines: Option<&[String]>) -> Option<String> {
    lines.filter(|lines| !lines.is_empty()).map(|lines| {
        let mut pem = lines.join("\n");
        if !pem.ends_with('\n') {
            pem.push('\n');
        }
        pem
    })
}

/// Lower VMess inbound TLS once during adapter construction.
#[cfg(feature = "transport_tls")]
pub fn lower_vmess_inbound_tls_options(
    tls: Option<&sb_config::ir::InboundTlsOptionsIR>,
) -> Result<Option<StandardTlsConfig>, String> {
    let Some(tls) = tls else {
        return Ok(None);
    };
    if !tls.enabled {
        return Ok(None);
    }
    if tls.insecure == Some(true) {
        return Err("vmess inbound TLS: insecure is client-only".to_string());
    }
    let config = StandardTlsConfig {
        server_name: tls.server_name.clone(),
        alpn: tls.alpn.clone().unwrap_or_default(),
        min_version: parse_version(tls.min_version.as_deref(), "vmess inbound TLS min_version")?,
        max_version: parse_version(tls.max_version.as_deref(), "vmess inbound TLS max_version")?,
        cipher_suites: tls.cipher_suites.clone().unwrap_or_default(),
        cert_path: tls.certificate_path.clone(),
        key_path: tls.key_path.clone(),
        cert_pem: joined_pem(tls.certificate.as_deref()),
        key_pem: joined_pem(tls.key.as_deref()),
        ..Default::default()
    };
    Ok(Some(config))
}

/// Lower VMess inbound TLS once during adapter construction.
#[cfg(feature = "transport_tls")]
pub fn lower_vmess_inbound_tls(ir: &InboundIR) -> Result<Option<StandardTlsConfig>, String> {
    if ir.tls.is_some() {
        return lower_vmess_inbound_tls_options(ir.tls.as_ref());
    }

    if ir.tls_enabled != Some(true) {
        return Ok(None);
    }
    let config = StandardTlsConfig {
        server_name: ir.tls_server_name.clone(),
        alpn: ir.tls_alpn.clone().unwrap_or_default(),
        cert_path: ir.tls_cert_path.clone(),
        key_path: ir.tls_key_path.clone(),
        cert_pem: ir.tls_cert_pem.clone(),
        key_pem: ir.tls_key_pem.clone(),
        ..Default::default()
    };
    Ok(Some(config))
}

/// Lower and build the reusable VMess inbound acceptor exactly once.
#[cfg(feature = "transport_tls")]
pub fn build_vmess_inbound_tls_options(
    tls: Option<&sb_config::ir::InboundTlsOptionsIR>,
    default_alpn: Option<&str>,
) -> Result<Option<tokio_rustls::TlsAcceptor>, String> {
    lower_vmess_inbound_tls_options(tls)?
        .map(|mut config| {
            if config.alpn.is_empty() {
                config.alpn.extend(default_alpn.map(str::to_string));
            }
            sb_transport::build_standard_tls_acceptor(&config)
                .map_err(|error| format!("vmess inbound TLS: {error}"))
        })
        .transpose()
}

/// Lower and build the reusable VMess inbound acceptor exactly once.
#[cfg(feature = "transport_tls")]
pub fn build_vmess_inbound_tls(
    ir: &InboundIR,
    default_alpn: Option<&str>,
) -> Result<Option<tokio_rustls::TlsAcceptor>, String> {
    lower_vmess_inbound_tls(ir)?
        .map(|mut config| {
            if config.alpn.is_empty() {
                config.alpn.extend(default_alpn.map(str::to_string));
            }
            sb_transport::build_standard_tls_acceptor(&config)
                .map_err(|error| format!("vmess inbound TLS: {error}"))
        })
        .transpose()
}

/// Lower VMess outbound TLS once during adapter construction.
#[cfg(feature = "transport_tls")]
pub fn lower_vmess_outbound_tls(ir: &OutboundIR) -> Result<Option<TlsConfig>, String> {
    if let Some(tls) = &ir.tls {
        if !tls.enabled {
            return Ok(None);
        }
        let config = StandardTlsConfig {
            server_name: tls.server_name.clone(),
            disable_sni: tls.disable_sni,
            alpn: tls.alpn.clone().unwrap_or_default(),
            insecure: tls.insecure,
            min_version: parse_version(
                tls.min_version.as_deref(),
                "vmess outbound TLS min_version",
            )?,
            max_version: parse_version(
                tls.max_version.as_deref(),
                "vmess outbound TLS max_version",
            )?,
            cipher_suites: tls.cipher_suites.clone().unwrap_or_default(),
            ca_paths: tls.certificate_path.iter().cloned().collect(),
            ca_pem: joined_pem(tls.certificate.as_deref()).into_iter().collect(),
            client_cert_path: tls.client_certificate_path.clone(),
            client_key_path: tls.client_key_path.clone(),
            client_cert_pem: joined_pem(tls.client_certificate.as_deref()),
            client_key_pem: joined_pem(tls.client_key.as_deref()),
            ..Default::default()
        };
        return Ok(Some(TlsConfig::Standard(config)));
    }

    let enabled = ir
        .transport
        .as_ref()
        .is_some_and(|layers| layers.iter().any(|layer| layer.eq_ignore_ascii_case("tls")));
    if !enabled {
        return Ok(None);
    }
    let config = StandardTlsConfig {
        server_name: ir.tls_sni.clone(),
        alpn: ir.tls_alpn.clone().unwrap_or_default(),
        insecure: ir.skip_cert_verify.unwrap_or(false),
        ca_paths: ir.tls_ca_paths.clone(),
        ca_pem: ir.tls_ca_pem.clone(),
        client_cert_path: ir.tls_client_cert_path.clone(),
        client_key_path: ir.tls_client_key_path.clone(),
        client_cert_pem: ir.tls_client_cert_pem.clone(),
        client_key_pem: ir.tls_client_key_pem.clone(),
        ..Default::default()
    };
    Ok(Some(TlsConfig::Standard(config)))
}

#[cfg(all(test, feature = "transport_tls"))]
mod tests {
    use super::*;
    use sb_config::ir::{InboundTlsOptionsIR, InboundType, OutboundTlsOptionsIR, OutboundType};

    fn certificate_lines() -> (Vec<String>, Vec<String>) {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
        (
            cert.pem().lines().map(str::to_string).collect(),
            key_pair
                .serialize_pem()
                .lines()
                .map(str::to_string)
                .collect(),
        )
    }

    #[test]
    fn inbound_builder_builds_inline_server_config_once() {
        let (certificate, key) = certificate_lines();
        let mut ir = InboundIR {
            ty: InboundType::Vmess,
            ..Default::default()
        };
        ir.tls = Some(InboundTlsOptionsIR {
            enabled: true,
            alpn: Some(vec!["h2".to_string()]),
            min_version: Some("1.2".to_string()),
            max_version: Some("1.3".to_string()),
            certificate: Some(certificate),
            key: Some(key),
            ..Default::default()
        });
        let lowered = lower_vmess_inbound_tls(&ir).unwrap().unwrap();
        assert_eq!(lowered.alpn, vec!["h2"]);
        assert_eq!(lowered.min_version, Some(TlsVersion::V1_2));
        assert_eq!(lowered.max_version, Some(TlsVersion::V1_3));
        assert!(build_vmess_inbound_tls(&ir, None).unwrap().is_some());
    }

    #[test]
    fn inbound_lowering_rejects_missing_material_and_invalid_version() {
        let mut ir = InboundIR {
            ty: InboundType::Vmess,
            ..Default::default()
        };
        ir.tls = Some(InboundTlsOptionsIR {
            enabled: true,
            min_version: Some("1.1".to_string()),
            ..Default::default()
        });
        assert!(lower_vmess_inbound_tls(&ir)
            .unwrap_err()
            .contains("unsupported TLS version"));

        ir.tls = Some(InboundTlsOptionsIR {
            enabled: true,
            ..Default::default()
        });
        let error = match build_vmess_inbound_tls(&ir, None) {
            Ok(_) => panic!("missing certificate must fail"),
            Err(error) => error,
        };
        assert!(error.contains("missing TLS server certificate"));
    }

    #[test]
    fn disabled_tls_lowers_to_plain() {
        let mut inbound = InboundIR {
            ty: InboundType::Vmess,
            ..Default::default()
        };
        inbound.tls = Some(InboundTlsOptionsIR::default());
        assert!(lower_vmess_inbound_tls(&inbound).unwrap().is_none());

        let mut outbound = OutboundIR {
            ty: OutboundType::Vmess,
            ..Default::default()
        };
        outbound.tls = Some(OutboundTlsOptionsIR::default());
        assert!(lower_vmess_outbound_tls(&outbound).unwrap().is_none());
    }

    #[test]
    fn outbound_lowering_preserves_verification_options() {
        let (certificate, _) = certificate_lines();
        let mut ir = OutboundIR {
            ty: OutboundType::Vmess,
            ..Default::default()
        };
        ir.tls = Some(OutboundTlsOptionsIR {
            enabled: true,
            server_name: Some("localhost".to_string()),
            disable_sni: true,
            alpn: Some(vec!["h2".to_string()]),
            min_version: Some("1.3".to_string()),
            max_version: Some("1.3".to_string()),
            certificate: Some(certificate),
            ..Default::default()
        });
        let Some(TlsConfig::Standard(lowered)) = lower_vmess_outbound_tls(&ir).unwrap() else {
            panic!("standard TLS must lower");
        };
        assert_eq!(lowered.server_name.as_deref(), Some("localhost"));
        assert!(lowered.disable_sni);
        assert_eq!(lowered.alpn, vec!["h2"]);
        assert_eq!(lowered.min_version, Some(TlsVersion::V1_3));
        assert_eq!(lowered.max_version, Some(TlsVersion::V1_3));
        assert_eq!(lowered.ca_pem.len(), 1);
    }
}
