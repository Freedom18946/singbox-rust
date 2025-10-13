//! E2E test for TLS SNI and ALPN sniffing in routing decisions
//!
//! This test validates that the routing engine correctly uses sniffed TLS SNI
//! and ALPN information to make routing decisions.

use sb_config::ir::{ConfigIR, RouteIR, RuleIR};
use sb_core::router::sniff::extract_sni_from_tls_client_hello;
use sb_core::routing::engine::{Engine, Input};

/// Build a minimal TLS ClientHello with SNI and ALPN
fn build_tls_client_hello(sni: &str, alpn: &str) -> Vec<u8> {
    let mut hs: Vec<u8> = Vec::new();
    hs.push(0x01); // Handshake type: ClientHello
    hs.extend_from_slice(&[0, 0, 0]); // Length placeholder
    hs.extend_from_slice(&[0x03, 0x03]); // Version TLS 1.2
    hs.extend_from_slice(&[0u8; 32]); // Random
    hs.push(0); // Session ID length
    hs.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]); // Cipher suites
    hs.push(1);
    hs.push(0); // Compression methods

    // Extensions
    let ext_len_pos = hs.len();
    hs.extend_from_slice(&[0x00, 0x00]); // Extensions length placeholder

    // SNI extension (0x0000)
    let mut ext: Vec<u8> = Vec::new();
    ext.extend_from_slice(&[0x00, 0x00]); // Extension type: server_name
    let ext_data_len_pos = ext.len();
    ext.extend_from_slice(&[0x00, 0x00]); // Extension data length placeholder
    let list_len_pos = ext.len();
    ext.extend_from_slice(&[0x00, 0x00]); // ServerNameList length placeholder

    // NameType(1)=0 (host_name)
    ext.push(0);
    let sni_bytes = sni.as_bytes();
    let sni_len = sni_bytes.len() as u16;
    ext.extend_from_slice(&sni_len.to_be_bytes());
    ext.extend_from_slice(sni_bytes);

    // Fill ServerNameList length
    let list_len = (1 + 2 + sni_bytes.len()) as u16;
    ext[list_len_pos..list_len_pos + 2].copy_from_slice(&list_len.to_be_bytes());
    let ext_data_len = (2 + list_len as usize) as u16;
    ext[ext_data_len_pos..ext_data_len_pos + 2].copy_from_slice(&ext_data_len.to_be_bytes());

    hs.extend_from_slice(&ext);

    // ALPN extension (0x0010)
    let mut alpn_ext: Vec<u8> = Vec::new();
    alpn_ext.extend_from_slice(&[0x00, 0x10]); // Extension type: ALPN
    let alpn_ext_data_len_pos = alpn_ext.len();
    alpn_ext.extend_from_slice(&[0x00, 0x00]); // Extension data length placeholder
    let alpn_list_len_pos = alpn_ext.len();
    alpn_ext.extend_from_slice(&[0x00, 0x00]); // ALPN list length placeholder

    // ALPN protocol
    let alpn_bytes = alpn.as_bytes();
    alpn_ext.push(alpn_bytes.len() as u8);
    alpn_ext.extend_from_slice(alpn_bytes);

    // Fill lengths
    let alpn_list_len = (1 + alpn_bytes.len()) as u16;
    alpn_ext[alpn_list_len_pos..alpn_list_len_pos + 2]
        .copy_from_slice(&alpn_list_len.to_be_bytes());
    let alpn_ext_data_len = (2 + alpn_list_len as usize) as u16;
    alpn_ext[alpn_ext_data_len_pos..alpn_ext_data_len_pos + 2]
        .copy_from_slice(&alpn_ext_data_len.to_be_bytes());

    hs.extend_from_slice(&alpn_ext);

    // Update extensions length
    let final_ext_len = (ext.len() + alpn_ext.len()) as u16;
    hs[ext_len_pos..ext_len_pos + 2].copy_from_slice(&final_ext_len.to_be_bytes());

    // Fill handshake length
    let hs_body_len = (hs.len() - 4) as u32;
    hs[1..4].copy_from_slice(&[
        (hs_body_len >> 16) as u8,
        (hs_body_len >> 8) as u8,
        hs_body_len as u8,
    ]);

    // TLS record wrapper
    let mut rec = Vec::new();
    rec.push(0x16); // Handshake
    rec.extend_from_slice(&[0x03, 0x03]); // Version
    let rec_len = hs.len() as u16;
    rec.extend_from_slice(&rec_len.to_be_bytes());
    rec.extend_from_slice(&hs);
    rec
}

#[test]
fn test_sni_based_routing() {
    // Build ClientHello with SNI
    let ch = build_tls_client_hello("api.example.com", "h2");
    let sni = extract_sni_from_tls_client_hello(&ch).expect("SNI extraction failed");
    assert_eq!(sni, "api.example.com");

    // Configure routing: api.example.com -> proxy, others -> direct
    let mut cfg = ConfigIR::default();
    cfg.route = RouteIR {
        rules: vec![RuleIR {
            domain: vec!["api.example.com".into()],
            outbound: Some("proxy".into()),
            ..Default::default()
        }],
        default: Some("direct".into()),
    };

    let eng = Engine::new(&cfg);

    // Test 1: SNI matches rule -> proxy
    let dec = eng.decide(
        &Input {
            host: "192.0.2.1", // IP address - routing should use SNI
            port: 443,
            network: "tcp",
            protocol: "tun",
            sniff_host: Some(&sni), // Provide sniffed SNI
            sniff_alpn: None,
        },
        false,
    );
    assert_eq!(
        dec.outbound, "proxy",
        "SNI-based routing should select proxy"
    );

    // Test 2: Without SNI, IP doesn't match -> direct
    let dec2 = eng.decide(
        &Input {
            host: "192.0.2.1",
            port: 443,
            network: "tcp",
            protocol: "tun",
            sniff_host: None,
            sniff_alpn: None,
        },
        false,
    );
    assert_eq!(
        dec2.outbound, "direct",
        "Without SNI, should fall back to default"
    );
}

#[test]
fn test_alpn_based_routing() {
    use sb_core::router::sniff::extract_alpn_from_tls_client_hello;

    // Build ClientHello with ALPN
    let ch = build_tls_client_hello("example.com", "h2");
    let alpn = extract_alpn_from_tls_client_hello(&ch).expect("ALPN extraction failed");
    assert_eq!(alpn, "h2");

    // Configure routing: h2 -> http2_proxy, http/1.1 -> http1_proxy
    let mut cfg = ConfigIR::default();
    cfg.route = RouteIR {
        rules: vec![
            RuleIR {
                alpn: vec!["h2".into()],
                outbound: Some("http2_proxy".into()),
                ..Default::default()
            },
            RuleIR {
                alpn: vec!["http/1.1".into()],
                outbound: Some("http1_proxy".into()),
                ..Default::default()
            },
        ],
        default: Some("direct".into()),
    };

    let eng = Engine::new(&cfg);

    // Test: ALPN h2 -> http2_proxy
    let dec = eng.decide(
        &Input {
            host: "example.com",
            port: 443,
            network: "tcp",
            protocol: "tun",
            sniff_host: None,
            sniff_alpn: Some(&alpn),
        },
        false,
    );
    assert_eq!(
        dec.outbound, "http2_proxy",
        "ALPN h2 should route to http2_proxy"
    );
}

#[test]
fn test_combined_sni_and_alpn_routing() {
    use sb_core::router::sniff::{
        extract_alpn_from_tls_client_hello, extract_sni_from_tls_client_hello,
    };

    // Build ClientHello with both SNI and ALPN
    let ch = build_tls_client_hello("api.cdn.example.com", "h2");
    let sni = extract_sni_from_tls_client_hello(&ch).expect("SNI extraction failed");
    let alpn = extract_alpn_from_tls_client_hello(&ch).expect("ALPN extraction failed");

    // Configure routing: api.cdn.example.com + h2 -> fast_proxy
    let mut cfg = ConfigIR::default();
    cfg.route = RouteIR {
        rules: vec![RuleIR {
            domain: vec!["cdn.example.com".into()],
            alpn: vec!["h2".into()],
            outbound: Some("fast_proxy".into()),
            ..Default::default()
        }],
        default: Some("direct".into()),
    };

    let eng = Engine::new(&cfg);

    // Test: Both SNI and ALPN match -> fast_proxy
    let dec = eng.decide(
        &Input {
            host: "192.0.2.1",
            port: 443,
            network: "tcp",
            protocol: "tun",
            sniff_host: Some(&sni),
            sniff_alpn: Some(&alpn),
        },
        false,
    );
    assert_eq!(
        dec.outbound, "fast_proxy",
        "Combined SNI+ALPN rule should match"
    );

    // Test: SNI matches but ALPN doesn't -> should not match
    let ch_http1 = build_tls_client_hello("api.cdn.example.com", "http/1.1");
    let alpn_http1 = extract_alpn_from_tls_client_hello(&ch_http1).expect("ALPN extraction failed");

    let dec2 = eng.decide(
        &Input {
            host: "192.0.2.1",
            port: 443,
            network: "tcp",
            protocol: "tun",
            sniff_host: Some(&sni),
            sniff_alpn: Some(&alpn_http1),
        },
        false,
    );
    assert_eq!(
        dec2.outbound, "direct",
        "Rule requires both SNI and ALPN to match"
    );
}
