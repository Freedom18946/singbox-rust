#![allow(dead_code)]
use std::io;

/// 将常见错误映射到有限集合，避免 label 爆炸
pub fn classify_io(e: &io::Error) -> &'static str {
    use io::ErrorKind::*;
    match e.kind() {
        ConnectionRefused => "refused",
        ConnectionReset => "reset",
        ConnectionAborted => "aborted",
        NotConnected => "not_connected",
        AddrInUse => "addr_in_use",
        AddrNotAvailable => "addr_unavail",
        TimedOut => "timeout",
        WouldBlock => "would_block",
        Interrupted => "interrupted",
        NetworkUnreachable => "net_unreach",
        HostUnreachable => "host_unreach",
        InvalidInput => "invalid",
        PermissionDenied => "perm",
        _ => "other",
    }
}

/// TLS/协议类（可逐步细化；未知一律 other）
pub fn classify_proto(err: &(dyn std::error::Error + 'static)) -> &'static str {
    // 轻量：仅根据字符串关键字粗略归类（避免引额外依赖）
    let s = err.to_string();
    if s.contains("certificate") {
        "tls_cert"
    } else if s.contains("verify") {
        "tls_verify"
    } else if s.contains("handshake") {
        "handshake"
    } else if s.contains("auth") {
        "auth"
    } else if s.contains("proxy") {
        "proxy"
    } else if s.contains("dns") {
        "dns"
    } else {
        "other"
    }
}
