#[cfg(feature = "proto_ss2022_min")]
#[test]
fn ss2022_min_bytes() {
    let h = sb_proto::ss2022_min::Ss2022Hello {
        method: "2022-blake3-aes-256-gcm".into(),
        password: "pass".into(),
        host: "example.com".into(),
        port: 8443,
    };
    let v = h.to_bytes();
    let s = String::from_utf8_lossy(&v);
    assert!(s.starts_with("SS2022\0"));
    assert!(s.contains("2022-blake3-aes-256-gcm\0pass\0example.com:8443"));
}
