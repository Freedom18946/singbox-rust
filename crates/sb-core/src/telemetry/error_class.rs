//! 兼容 1.82：避免使用不稳定的 `io_error_more` 变体
#![allow(dead_code)]
use std::io::{Error, ErrorKind};

/// 将常见错误映射到有限集合，避免 label 爆炸
#[inline]
pub fn classify_io(err: &Error) -> &'static str {
    match err.kind() {
        ErrorKind::ConnectionRefused => "conn_refused",
        ErrorKind::TimedOut => "timeout",
        ErrorKind::ConnectionReset => "conn_reset",
        ErrorKind::BrokenPipe => "broken_pipe",
        ErrorKind::AddrInUse => "addr_in_use",
        ErrorKind::AddrNotAvailable => "addr_unavail",
        ErrorKind::NotFound => "not_found",
        ErrorKind::PermissionDenied => "perm",
        ErrorKind::Interrupted => "interrupted",
        ErrorKind::WouldBlock => "would_block",
        ErrorKind::AlreadyExists => "exists",
        ErrorKind::InvalidInput => "invalid_input",
        ErrorKind::InvalidData => "invalid_data",
        ErrorKind::UnexpectedEof => "unexpected_eof",
        ErrorKind::WriteZero => "write_zero",
        _ => {
            #[cfg(unix)]
            {
                if let Some(code) = err.raw_os_error() {
                    if code == 101 {
                        return "net_unreach";
                    } // ENETUNREACH
                    if code == 113 {
                        return "host_unreach";
                    } // EHOSTUNREACH
                }
            }
            "other"
        }
    }
}

// 若原有代码对外暴露的是 `error_class(err: &Error) -> &'static str`
// 可保持同名包装，避免到处改调用点：
#[inline]
pub fn error_class(err: &Error) -> &'static str {
    classify_io(err)
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
