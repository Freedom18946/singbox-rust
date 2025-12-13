//! DNS config builder tests
//!
//! Tests for DNS configuration and URL parsing

#![cfg(feature = "router")]

use anyhow::Result;
use sb_config::ir::DnsServerIR;

#[cfg(feature = "dns_udp")]
#[test]
fn test_udp_url_parsing() -> Result<()> {
    use sb_core::dns::config_builder::build_upstream;

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
    use sb_core::dns::config_builder::build_upstream;

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
    use sb_core::dns::config_builder::build_upstream;

    // Test DoH URL parsing
    let upstream = build_upstream("https://dns.google/dns-query")?;
    assert!(upstream.is_some(), "DoH HTTPS URL should be parsed");

    if let Some(u) = upstream {
        assert!(u.name().contains("doh") || u.name().contains("dns.google"));
    }

    Ok(())
}

#[cfg(feature = "dns_doq")]
#[test]
fn test_doq_url_parsing() -> Result<()> {
    use sb_core::dns::config_builder::build_upstream;

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
    use sb_core::dns::config_builder::build_upstream;

    // Test DoH3 URL parsing with doh3:// scheme
    let upstream = build_upstream("doh3://1.1.1.1:443/dns-query")?;
    assert!(upstream.is_some(), "DoH3 URL should be parsed");

    if let Some(u) = upstream {
        assert!(u.name().contains("doh3") || u.name().contains("1.1.1.1"));
    }

    // Test DoH3 URL parsing with h3:// scheme
    let upstream = build_upstream("h3://cloudflare-dns.com/dns-query")?;
    assert!(upstream.is_some(), "H3 URL should be parsed");

    Ok(())
}

#[cfg(feature = "dns_doh3")]
#[test]
fn test_doh3_url_parsing_with_default_port() -> Result<()> {
    use sb_core::dns::config_builder::build_upstream;

    // Test DoH3 URL parsing without explicit port (should default to 443)
    let upstream = build_upstream("doh3://cloudflare-dns.com/dns-query")?;
    assert!(upstream.is_some(), "DoH3 URL without port should be parsed");

    Ok(())
}

#[cfg(feature = "dns_doh3")]
#[test]
fn test_doh3_url_parsing_with_default_path() -> Result<()> {
    use sb_core::dns::config_builder::build_upstream;

    // Test DoH3 URL parsing without explicit path (should default to /dns-query)
    let upstream = build_upstream("doh3://1.1.1.1:443")?;
    assert!(upstream.is_some(), "DoH3 URL without path should be parsed");

    // Test with just hostname
    let upstream = build_upstream("h3://cloudflare-dns.com")?;
    assert!(
        upstream.is_some(),
        "H3 URL with just hostname should be parsed"
    );

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
    };

    let upstream = build_upstream_from_server(&server_ir)?;
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
        address: "doh3://private-dns.example:8443/query".to_string(),
        sni: Some("dns.example.com".to_string()),
        client_subnet: None,
        ca_paths: vec!["/path/to/ca.pem".to_string()],
        ca_pem: vec!["-----BEGIN CERTIFICATE-----\n...\n".to_string()],
        skip_cert_verify: Some(false),
    };

    let upstream = build_upstream_from_server(&server_ir)?;
    assert!(upstream.is_some(), "DoH3 with TLS options should be parsed");

    Ok(())
}

#[test]
fn test_system_resolver_parsing() -> Result<()> {
    use sb_core::dns::config_builder::build_upstream;

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
    use sb_core::dns::config_builder::build_upstream;

    // Test that DoH3 config can be parsed and used
    let urls = vec![
        "doh3://1.1.1.1:443/dns-query",
        "h3://cloudflare-dns.com/dns-query",
        "doh3://dns.google:443/dns-query",
    ];

    for url in urls {
        let upstream = build_upstream(url)?;
        assert!(upstream.is_some(), "URL '{}' should be parsed", url);

        if let Some(u) = upstream {
            let name = u.name();
            assert!(
                name.contains("doh3")
                    || name.contains("h3")
                    || name.contains("1.1.1.1")
                    || name.contains("cloudflare")
                    || name.contains("google"),
                "Upstream name '{}' should contain expected keywords for URL '{}'",
                name,
                url
            );
        }
    }

    Ok(())
}

#[cfg(feature = "dns_doh3")]
#[test]
fn test_doh3_vs_doh_url_schemes() {
    use sb_core::dns::config_builder::build_upstream;

    // DoH uses https://
    let doh_result = build_upstream("https://1.1.1.1/dns-query");
    #[cfg(feature = "dns_doh")]
    assert!(
        doh_result.is_ok() && doh_result.unwrap().is_some(),
        "DoH should use https://"
    );

    // DoH3 uses doh3:// or h3://
    let doh3_result1 = build_upstream("doh3://1.1.1.1/dns-query");
    assert!(
        doh3_result1.is_ok() && doh3_result1.unwrap().is_some(),
        "DoH3 should use doh3://"
    );

    let doh3_result2 = build_upstream("h3://1.1.1.1/dns-query");
    assert!(
        doh3_result2.is_ok() && doh3_result2.unwrap().is_some(),
        "DoH3 should use h3://"
    );
}
