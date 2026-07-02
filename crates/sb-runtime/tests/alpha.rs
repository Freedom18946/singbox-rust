//! alpha golden tests (deterministic)
#![cfg(feature = "handshake_alpha")]
use sb_runtime::prelude::*;
#[test]
fn trojan_seed42_len_head() {
    let t = sb_runtime::protocols::trojan::Trojan::new("example.com".into(), 443);
    let bytes = t.encode_init(42);
    assert!(bytes.len() >= 20, "len too small");
    // 只断言前缀特征，避免实现细节锁死
    assert_eq!(
        u16::from_le_bytes([bytes[0], bytes[1]]) as usize,
        "example.com".len()
    );
}
#[test]
fn vmess_seed42_magic() {
    let v = sb_runtime::protocols::vmess::Vmess::new("example.com".into(), 443);
    let b = v.encode_init(42);
    assert!(b.starts_with(&[0x56, 0x4D, 0x45, 0x53, 0x53, 0, 0, 1]));
}
