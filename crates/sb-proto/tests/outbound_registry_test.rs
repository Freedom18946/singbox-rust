#[cfg(feature = "outbound_registry")]
#[test]
fn registry_insert_and_lookup() {
    use sb_proto::outbound_registry::{OutboundKind, OutboundSpec, Registry};
    let mut r = Registry::new();
    r.insert(OutboundSpec {
        name: "a".into(),
        kind: OutboundKind::Trojan,
        password: Some("p".into()),
        method: None,
    });
    r.insert(OutboundSpec {
        name: "b".into(),
        kind: OutboundKind::Ss2022,
        password: Some("q".into()),
        method: Some("2022-blake3-aes-256-gcm".into()),
    });
    assert_eq!(r.names(), vec!["a".to_string(), "b".to_string()]);
    assert_eq!(r.get("a").unwrap().password.as_deref(), Some("p"));
}
