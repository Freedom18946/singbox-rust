#[cfg(feature = "proto_trojan_min")]
#[test]
fn trojan_min_bytes() {
    use sb_proto::trojan_min::TrojanHello;
    let h = TrojanHello {
        password: "pass".into(),
        host: "example.com".into(),
        port: 443,
    };
    let v = h.to_bytes();
    let s = String::from_utf8(v).unwrap();
    assert!(s.starts_with("pass\r\nCONNECT example.com:443\r\n\r\n"));
}
