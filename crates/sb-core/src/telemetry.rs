use crate::outbound::{OutboundKind, RouteTarget};
use std::io;

pub mod dial;
pub mod error_class;

#[inline]
pub fn err_kind(e: &io::Error) -> &'static str {
    use io::ErrorKind::{TimedOut, ConnectionRefused, ConnectionReset, ConnectionAborted, BrokenPipe, AddrInUse, AddrNotAvailable, NotFound, InvalidInput};
    match e.kind() {
        TimedOut => "timeout",
        ConnectionRefused => "refused",
        ConnectionReset | ConnectionAborted | BrokenPipe => "reset",
        AddrInUse | AddrNotAvailable | NotFound | InvalidInput => "addr",
        _ => "other",
    }
}

// =========================
// Metrics helpers (no-op when feature off)
// =========================

#[cfg(feature = "metrics")]
#[inline]
fn cnt(name: &'static str, kv: &[(&'static str, &'static str)], v: u64) {
    // 展开成宏参数（宏需要字面量key，这里 values 仍是 &str）
    match kv {
        // 常见标签组合专门展开（避免动态拼接导致的宏不兼容）
        [("kind", kind), ("result", result)] => {
            metrics::counter!(name, "kind"=>*kind, "result"=>*result).increment(v);
        }
        [("kind", kind), ("result", result), ("err", err)] => {
            metrics::counter!(name, "kind"=>*kind, "result"=>*result, "err"=>*err).increment(v);
        }
        [("label", label), ("dir", dir)] => {
            metrics::counter!(name, "label"=>*label, "dir"=>*dir).increment(v);
        }
        [("label", label), ("result", result), ("err", err)] => {
            metrics::counter!(name, "label"=>*label, "result"=>*result, "err"=>*err).increment(v);
        }
        [("mode", mode), ("ttype", ttype)] => {
            // 低基数路由选择：仅记录类型，不记录具体"命名出站"字符串，避免高基数
            metrics::counter!(name, "mode"=>*mode, "ttype"=>*ttype).increment(v);
        }
        _ => {
            // 兜底：只打 name（不建议用）
            metrics::counter!(name).increment(v);
        }
    }
}
#[cfg(not(feature = "metrics"))]
#[inline]
const fn cnt(_name: &'static str, _kv: &[(&'static str, &'static str)], _v: u64) {}

#[inline]
pub fn outbound_connect(kind: &'static str, result: &'static str, err: Option<&'static str>) {
    match err {
        Some(e) => cnt(
            "sb_outbound_connect_total",
            &[("kind", kind), ("result", result), ("err", e)],
            1,
        ),
        None => cnt(
            "sb_outbound_connect_total",
            &[("kind", kind), ("result", result)],
            1,
        ),
    }
}

#[inline]
pub fn outbound_handshake(kind: &'static str, result: &'static str, err: Option<&'static str>) {
    match err {
        Some(e) => cnt(
            "sb_outbound_handshake_total",
            &[("kind", kind), ("result", result), ("err", e)],
            1,
        ),
        None => cnt(
            "sb_outbound_handshake_total",
            &[("kind", kind), ("result", result)],
            1,
        ),
    }
}

#[inline]
pub fn inbound_parse(kind: &'static str, result: &'static str, reason: &'static str) {
    // 解析阶段多是协议错误，使用 reason 代替 err 标签
    cnt(
        "sb_inbound_parse_total",
        &[("label", kind), ("result", result), ("err", reason)],
        1,
    );
}

#[inline]
pub fn inbound_forward(label: &'static str, result: &'static str, err: Option<&'static str>) {
    match err {
        Some(e) => cnt(
            "sb_inbound_forward_total",
            &[("label", label), ("result", result), ("err", e)],
            1,
        ),
        None => cnt(
            "sb_inbound_forward_total",
            &[("label", label), ("result", result)],
            1,
        ),
    }
}

#[inline]
pub fn router_select(mode: &'static str, target: &RouteTarget) {
    let ttype: &'static str = match target {
        RouteTarget::Kind(k) => {
            let kind = match k {
                OutboundKind::Direct => "direct",
                OutboundKind::Socks => "socks5",
                OutboundKind::Http => "http",
                OutboundKind::Block => "block",
                #[cfg(feature = "out_trojan")]
                OutboundKind::Trojan => "trojan",
                #[cfg(feature = "out_ss")]
                OutboundKind::Shadowsocks => "shadowsocks",
                #[cfg(feature = "out_shadowtls")]
                OutboundKind::ShadowTls => "shadowtls",
                #[cfg(feature = "out_naive")]
                OutboundKind::Naive => "naive",
                #[cfg(feature = "out_vless")]
                OutboundKind::Vless => "vless",
                #[cfg(feature = "out_vmess")]
                OutboundKind::Vmess => "vmess",
                #[cfg(feature = "out_tuic")]
                OutboundKind::Tuic => "tuic",
                #[cfg(feature = "out_hysteria2")]
                OutboundKind::Hysteria2 => "hysteria2",
                #[cfg(feature = "out_wireguard")]
                OutboundKind::WireGuard => "wireguard",
                #[cfg(feature = "out_ssh")]
                OutboundKind::Ssh => "ssh",
            };
            let _ = kind; // 值不再作为标签输出，避免高基数
            "kind"
        }
        RouteTarget::Named(_name) => "named",
    };
    cnt(
        "sb_router_select_total",
        &[("mode", mode), ("ttype", ttype)],
        1,
    );
}

/// HTTP CONNECT 状态分类（传入 status code，返回 err 标签 & 类别）
#[inline]
pub fn http_status_err(status: u16) -> (&'static str, &'static str) {
    let class = match status {
        200 => return ("ok", "2xx"),
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "other",
    };
    ("status", class)
}

/// SOCKS5 REP 映射为 err 标签短语
#[inline]
pub const fn socks5_rep_err(rep: u8) -> &'static str {
    match rep {
        0x00 => "ok",
        0x01 => "general",
        0x02 => "rule", // disallowed by ruleset
        0x03 => "net",
        0x04 => "host",
        0x05 => "refused",
        0x06 => "ttl",
        0x07 => "cmd",
        0x08 => "atyp",
        _ => "other",
    }
}
