//! R135: Tests for SS2022 TLS first packet builder (R133)

#[cfg(feature = "proto_ss2022_tls_first")]
#[test]
fn test_build_tls_first_packet() {
    use sb_proto::ss2022_harness::{build_tls_first_packet, preview_tls_first_packet};

    let payload = b"test payload";

    // Test basic packet building
    let packet = build_tls_first_packet(payload, Some("example.com"));

    // Basic validation
    assert!(!packet.is_empty());
    assert_eq!(packet[0], 0x16); // TLS Handshake record type
    assert_eq!(packet[1], 0x03); // TLS version major
    assert_eq!(packet[2], 0x03); // TLS version minor (1.2)

    // Test without SNI
    let packet_no_sni = build_tls_first_packet(payload, None);
    assert!(!packet_no_sni.is_empty());
    assert_eq!(packet_no_sni[0], 0x16);

    // Test with different SNI
    let packet_custom_sni = build_tls_first_packet(payload, Some("test.example.org"));
    assert!(!packet_custom_sni.is_empty());
    assert_eq!(packet_custom_sni[0], 0x16);

    // Test preview function
    let preview = preview_tls_first_packet(payload);
    assert!(preview.contains("0000:"));
    assert!(preview.contains("16 03 03")); // TLS record header
}

#[cfg(feature = "proto_ss2022_tls_first")]
#[test]
fn test_packet_structure() {
    use sb_proto::ss2022_harness::build_tls_first_packet;

    let payload = b"hello";
    let packet = build_tls_first_packet(payload, Some("test.com"));

    // Validate TLS record structure
    assert_eq!(packet[0], 0x16); // Content Type: Handshake
    assert_eq!(packet[1..3], [0x03, 0x03]); // Version: TLS 1.2

    // Check record length field exists
    let record_length = u16::from_be_bytes([packet[3], packet[4]]) as usize;
    assert_eq!(packet.len(), record_length + 5); // 5 bytes for TLS record header

    // Validate Client Hello structure
    assert_eq!(packet[5], 0x01); // Handshake Type: Client Hello

    // Validate minimum packet size (should have all required TLS fields)
    assert!(packet.len() > 50); // Basic TLS Client Hello should be larger than 50 bytes
}

#[cfg(feature = "proto_ss2022_tls_first")]
#[tokio::test]
async fn test_connect_env_tls() {
    use sb_proto::ss2022_harness::connect_env;

    // Test TLS connect (should work with the new feature)
    let result = connect_env("httpbin.org", 443, 5000, true).await;

    match result {
        Ok(report) => {
            assert_eq!(report.path, "tls");
            assert!(report.elapsed_ms > 0);
        }
        Err(e) => {
            // TLS might fail in test environment, but should not be FeatureDisabled
            let err_str = e.to_string();
            assert!(!err_str.contains("feature not enabled"));
        }
    }
}

#[cfg(feature = "proto_ss2022_min")]
#[tokio::test]
async fn test_connect_env_tcp() {
    use sb_proto::ss2022_harness::connect_env;

    // Test TCP connect (should always work)
    let result = connect_env("httpbin.org", 80, 5000, false).await;

    match result {
        Ok(report) => {
            assert_eq!(report.path, "tcp");
            assert!(report.elapsed_ms > 0);
        }
        Err(_) => {
            // TCP connection might fail in test environment, but should not panic
        }
    }
}
