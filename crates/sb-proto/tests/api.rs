//! API shape tests to verify all public types compile correctly.

use sb_proto::{IoStream, ProtoError, Target};

#[test]
fn target_api() {
    // Verify Target construction and methods
    let target = Target::new("example.com", 443);
    assert_eq!(target.host(), "example.com");
    assert_eq!(target.port(), 443);

    // Test into_parts
    let (host, port) = target.into_parts();
    assert_eq!(host, "example.com");
    assert_eq!(port, 443);

    // Test Clone, PartialEq, Hash traits
    let t1 = Target::new("test.com", 80);
    let t2 = Target::new("test.com", 80);
    assert_eq!(t1, t2);
}

#[test]
fn trojan_hello_api() {
    use sb_proto::trojan::TrojanHello;

    let hello = TrojanHello {
        password: "secret".to_string(),
        host: "example.com".to_string(),
        port: 443,
    };

    let bytes = hello.to_bytes();
    assert!(!bytes.is_empty());

    // Verify format: password\r\nCONNECT host:port\r\n\r\n
    let s = String::from_utf8_lossy(&bytes);
    assert!(s.contains("secret"));
    assert!(s.contains("CONNECT"));
    assert!(s.contains("example.com:443"));
}

#[test]
fn ss2022_hello_api() {
    use sb_proto::ss2022::Ss2022Hello;

    let hello = Ss2022Hello {
        method: "2022-blake3-aes-256-gcm".to_string(),
        password: "testpass".to_string(),
        host: "example.com".to_string(),
        port: 443,
    };

    let bytes = hello.to_bytes();
    assert!(!bytes.is_empty());

    // Verify format starts with SS2022 marker
    assert!(bytes.starts_with(b"SS2022\0"));
}

#[test]
fn proto_error_api() {
    // Test error variants
    let err = ProtoError::NotImplemented;
    assert_eq!(err.to_string(), "not implemented");

    let err = ProtoError::InvalidConfig("test error".to_string());
    assert!(err.to_string().contains("test error"));

    // Test From<std::io::Error> conversion
    let io_err = std::io::Error::other("test");
    let proto_err: ProtoError = io_err.into();
    assert!(proto_err.to_string().contains("test"));
}

#[test]
fn io_stream_trait() {
    // Verify IoStream is implemented for common types
    fn assert_io_stream<T: IoStream>() {}

    // TcpStream should implement IoStream
    assert_io_stream::<tokio::net::TcpStream>();
}

#[cfg(feature = "outbound_registry")]
#[test]
fn registry_api() {
    use sb_proto::{OutboundKind, OutboundSpec, Registry};

    let mut registry = Registry::new();

    // Test Trojan spec
    let spec = OutboundSpec {
        name: "trojan-test".to_string(),
        kind: OutboundKind::Trojan,
        password: Some("password123".to_string()),
        method: None,
    };
    registry.insert(spec);

    // Test SS2022 spec
    let spec = OutboundSpec {
        name: "ss2022-test".to_string(),
        kind: OutboundKind::Ss2022,
        password: Some("pass".to_string()),
        method: Some("2022-blake3-aes-256-gcm".to_string()),
    };
    registry.insert(spec);

    // Verify retrieval
    let names = registry.names();
    assert_eq!(names.len(), 2);
    assert!(names.contains(&"trojan-test".to_string()));
    assert!(names.contains(&"ss2022-test".to_string()));

    let spec = registry.get("trojan-test").unwrap();
    assert_eq!(spec.kind, OutboundKind::Trojan);
}

#[cfg(feature = "outbound_registry")]
#[test]
fn ss2022_hello_bytes_api() {
    use sb_proto::{ss2022_hello_bytes, OutboundKind, OutboundSpec, Registry};

    let mut registry = Registry::new();
    let spec = OutboundSpec {
        name: "test".to_string(),
        kind: OutboundKind::Ss2022,
        password: Some("testpass".to_string()),
        method: Some("2022-blake3-aes-256-gcm".to_string()),
    };
    registry.insert(spec);

    let bytes = ss2022_hello_bytes("test", &registry, "example.com", 443).unwrap();
    assert!(!bytes.is_empty());
    assert!(bytes.starts_with(b"SS2022\0"));
}
