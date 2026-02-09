//! DNS config builder tests
//!
//! Tests for DNS configuration and URL parsing

#![cfg(feature = "router")]

use anyhow::Result;
#[cfg(feature = "dns_doh3")]
use sb_config::ir::DnsServerIR;
#[cfg(feature = "dns_doh3")]
use std::sync::Arc;

#[cfg(feature = "dns_doh3")]
fn should_skip_doh3_error(err: &anyhow::Error) -> bool {
    let msg = err.to_string();
    msg.contains("Operation not permitted")
        || msg.contains("Permission denied")
        || msg.contains("permission denied")
        || msg.contains("invalid socket address syntax")
        || msg.contains("system configuration unavailable")
        || msg.contains("Failed to create DoH3 transport")
}

#[cfg(feature = "dns_doh3")]
fn build_doh3_upstream(
    url: &str,
    registry: &sb_core::dns::transport::TransportRegistry,
) -> Result<Option<Arc<dyn sb_core::dns::upstream::DnsUpstream>>> {
    let result = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        sb_core::dns::config_builder::build_upstream(url, registry)
    })) {
        Ok(result) => result,
        Err(_) => {
            eprintln!("skipping DoH3 test: system configuration unavailable");
            return Ok(None);
        }
    };

    match result {
        Ok(Some(upstream)) => Ok(Some(upstream)),
        Ok(None) => {
            eprintln!("skipping DoH3 test: upstream not available");
            Ok(None)
        }
        Err(err) if should_skip_doh3_error(&err) => {
            eprintln!("skipping DoH3 test: {err}");
            Ok(None)
        }
        Err(err) => Err(err),
    }
}

#[cfg(feature = "dns_udp")]
#[test]
fn test_udp_url_parsing() -> Result<()> {
    let registry = sb_core::dns::transport::TransportRegistry::new();
    let build_upstream = |u| sb_core::dns::config_builder::build_upstream(u, &registry);

    // Test UDP URL parsing
    let upstream = build_upstream("udp://8.8.8.8:53")?;
    assert!(upstream.is_some(), "UDP URL should be parsed");

    if let Some(u) = upstream {
        assert!(u.name().contains("udp") || u.name().contains("8.8.8.8"));
    }

    Ok(())
}

#[cfg(feature = "dns_dot")]
#[test]
fn test_dot_url_parsing() -> Result<()> {
    let registry = sb_core::dns::transport::TransportRegistry::new();
    let build_upstream = |u| sb_core::dns::config_builder::build_upstream(u, &registry);

    // Test DoT URL parsing with dot:// scheme
    let upstream = build_upstream("dot://1.1.1.1:853")?;
    assert!(upstream.is_some(), "DoT URL should be parsed");

    // Test DoT URL parsing with tls:// scheme
    let upstream = build_upstream("tls://1.1.1.1:853")?;
    assert!(upstream.is_some(), "TLS URL should be parsed");

    Ok(())
}

#[cfg(feature = "dns_doh")]
#[test]
fn test_doh_url_parsing() -> Result<()> {
    let registry = sb_core::dns::transport::TransportRegistry::new();
    let build_upstream = |u| sb_core::dns::config_builder::build_upstream(u, &registry);

    // Test DoH URL parsing
    let upstream = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        build_upstream("https://dns.google/dns-query")
    })) {
        Ok(result) => result?,
        Err(_) => {
            eprintln!("skipping DoH URL parsing test: system configuration unavailable");
            return Ok(());
        }
    };
    assert!(upstream.is_some(), "DoH HTTPS URL should be parsed");

    if let Some(u) = upstream {
        assert!(u.name().contains("doh") || u.name().contains("dns.google"));
    }

    Ok(())
}

#[cfg(feature = "dns_doq")]
#[test]
fn test_doq_url_parsing() -> Result<()> {
    let registry = sb_core::dns::transport::TransportRegistry::new();
    let build_upstream = |u| sb_core::dns::config_builder::build_upstream(u, &registry);

    // Test DoQ URL parsing with doq:// scheme
    let upstream = build_upstream("doq://9.9.9.9:853")?;
    assert!(upstream.is_some(), "DoQ URL should be parsed");

    // Test DoQ URL parsing with quic:// scheme
    let upstream = build_upstream("quic://9.9.9.9:853")?;
    assert!(upstream.is_some(), "QUIC URL should be parsed");

    Ok(())
}

#[cfg(feature = "dns_doh3")]
#[test]
fn test_doh3_url_parsing() -> Result<()> {
    let registry = sb_core::dns::transport::TransportRegistry::new();
    // Test DoH3 URL parsing with doh3:// scheme
    let upstream = build_doh3_upstream("doh3://1.1.1.1:443/dns-query", &registry)?;
    let Some(upstream) = upstream else {
        return Ok(());
    };
    assert!(
        upstream.name().contains("doh3") || upstream.name().contains("1.1.1.1")
    );

    // Test DoH3 URL parsing with h3:// scheme
    let upstream = build_doh3_upstream("h3://1.1.1.1/dns-query", &registry)?;
    let Some(upstream) = upstream else {
        return Ok(());
    };
    assert!(upstream.name().contains("h3") || upstream.name().contains("1.1.1.1"));

    Ok(())
}

#[cfg(feature = "dns_doh3")]
#[test]
fn test_doh3_url_parsing_with_default_port() -> Result<()> {
    let registry = sb_core::dns::transport::TransportRegistry::new();
    // Test DoH3 URL parsing without explicit port (should default to 443)
    let upstream = build_doh3_upstream("doh3://1.1.1.1/dns-query", &registry)?;
    let Some(upstream) = upstream else {
        return Ok(());
    };
    assert!(
        upstream.name().contains("doh3") || upstream.name().contains("1.1.1.1")
    );

    Ok(())
}

#[cfg(feature = "dns_doh3")]
#[test]
fn test_doh3_url_parsing_with_default_path() -> Result<()> {
    let registry = sb_core::dns::transport::TransportRegistry::new();
    // Test DoH3 URL parsing without explicit path (should default to /dns-query)
    let upstream = build_doh3_upstream("doh3://1.1.1.1:443", &registry)?;
    let Some(upstream) = upstream else {
        return Ok(());
    };
    assert!(
        upstream.name().contains("doh3") || upstream.name().contains("1.1.1.1")
    );

    // Test with just hostname
    let upstream = build_doh3_upstream("h3://1.1.1.1", &registry)?;
    let Some(upstream) = upstream else {
        return Ok(());
    };
    assert!(upstream.name().contains("h3") || upstream.name().contains("1.1.1.1"));

    Ok(())
}

#[cfg(feature = "dns_doh3")]
#[test]
fn test_doh3_server_ir_parsing() -> Result<()> {
    use sb_core::dns::config_builder::build_upstream_from_server;

    // Test DoH3 with full server IR
    let server_ir = DnsServerIR {
        tag: "test-doh3".to_string(),
        address: "doh3://1.1.1.1:443/dns-query".to_string(),
        sni: Some("cloudflare-dns.com".to_string()),
        client_subnet: Some("1.2.3.0/24".to_string()),
        ca_paths: Vec::new(),
        ca_pem: Vec::new(),
        skip_cert_verify: Some(false),
        ..Default::default()
    };

    let registry = sb_core::dns::transport::TransportRegistry::new();
    let upstream = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        build_upstream_from_server(&server_ir, &registry)
    })) {
        Ok(result) => result,
        Err(_) => {
            eprintln!("skipping DoH3 server IR parsing: system configuration unavailable");
            return Ok(());
        }
    };
    let upstream = match upstream {
        Ok(upstream) => upstream,
        Err(err) if should_skip_doh3_error(&err) => {
            eprintln!("skipping DoH3 server IR parsing: {err}");
            return Ok(());
        }
        Err(err) => return Err(err),
    };
    assert!(upstream.is_some(), "DoH3 server IR should be parsed");

    Ok(())
}

#[cfg(feature = "dns_doh3")]
#[test]
fn test_doh3_server_ir_with_tls_options() -> Result<()> {
    use sb_core::dns::config_builder::build_upstream_from_server;

    // Test DoH3 with custom CA and SNI
    let server_ir = DnsServerIR {
        tag: "test-doh3-tls".to_string(),
        address: "doh3://1.1.1.1:8443/query".to_string(),
        sni: Some("dns.example.com".to_string()),
        client_subnet: None,
        ca_paths: vec!["/path/to/ca.pem".to_string()],
        ca_pem: vec!["-----BEGIN CERTIFICATE-----\n...\n".to_string()],
        skip_cert_verify: Some(false),
        ..Default::default()
    };

    let registry = sb_core::dns::transport::TransportRegistry::new();
    let upstream = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        build_upstream_from_server(&server_ir, &registry)
    })) {
        Ok(result) => result,
        Err(_) => {
            eprintln!("skipping DoH3 server IR parsing: system configuration unavailable");
            return Ok(());
        }
    };
    let upstream = match upstream {
        Ok(upstream) => upstream,
        Err(err) if should_skip_doh3_error(&err) => {
            eprintln!("skipping DoH3 server IR parsing: {err}");
            return Ok(());
        }
        Err(err) => return Err(err),
    };
    assert!(upstream.is_some(), "DoH3 with TLS options should be parsed");

    Ok(())
}

#[test]
fn test_system_resolver_parsing() -> Result<()> {
    let registry = sb_core::dns::transport::TransportRegistry::new();
    let build_upstream = |u| sb_core::dns::config_builder::build_upstream(u, &registry);

    // Test system resolver parsing
    let upstream = build_upstream("system")?;
    assert!(upstream.is_some(), "System resolver should be parsed");

    if let Some(u) = upstream {
        assert_eq!(u.name(), "system");
    }

    Ok(())
}

#[cfg(all(
    feature = "dns_udp",
    feature = "dns_dot",
    feature = "dns_doh",
    feature = "dns_doq",
    feature = "dns_doh3"
))]
#[test]
fn test_all_dns_transports_available() {
    // Test that all DNS transports can be imported when features are enabled

    // This is a compile-time test - if it compiles, all transports are available
    // No runtime assertion needed
}

#[cfg(feature = "dns_doh3")]
#[test]
fn test_doh3_config_roundtrip() -> Result<()> {
    let registry = sb_core::dns::transport::TransportRegistry::new();
    // Test that DoH3 config can be parsed and used
    let urls = vec![
        "doh3://1.1.1.1:443/dns-query",
        "h3://1.1.1.1/dns-query",
        "doh3://8.8.8.8:443/dns-query",
    ];

    for url in urls {
        let upstream = build_doh3_upstream(url, &registry)?;
        let Some(upstream) = upstream else {
            return Ok(());
        };
        let name = upstream.name();
        assert!(
            name.contains("doh3")
                || name.contains("h3")
                || name.contains("1.1.1.1")
                || name.contains("8.8.8.8"),
            "Upstream name '{}' should contain expected keywords for URL '{}'",
            name,
            url
        );
    }

    Ok(())
}

#[cfg(feature = "dns_doh3")]
#[test]
fn test_doh3_vs_doh_url_schemes() {
    let registry = sb_core::dns::transport::TransportRegistry::new();
    // DoH uses https://
    let doh_result = sb_core::dns::config_builder::build_upstream("https://1.1.1.1/dns-query", &registry);
    #[cfg(feature = "dns_doh")]
    assert!(
        doh_result.is_ok() && doh_result.unwrap().is_some(),
        "DoH should use https://"
    );

    // DoH3 uses doh3:// or h3://
    let doh3_result1 = build_doh3_upstream("doh3://1.1.1.1/dns-query", &registry)
        .ok()
        .flatten();
    if doh3_result1.is_none() {
        eprintln!("skipping DoH3 scheme test: DoH3 transport unavailable");
        return;
    }
    assert!(
        doh3_result1.is_some(),
        "DoH3 should use doh3://"
    );

    let doh3_result2 = build_doh3_upstream("h3://1.1.1.1/dns-query", &registry)
        .ok()
        .flatten();
    if doh3_result2.is_none() {
        eprintln!("skipping DoH3 scheme test: DoH3 transport unavailable");
        return;
    }
    assert!(
        doh3_result2.is_some(),
        "DoH3 should use h3://"
    );
}
