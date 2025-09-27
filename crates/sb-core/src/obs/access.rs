use std::collections::BTreeMap;
use std::time::{SystemTime, UNIX_EPOCH};

fn enabled() -> bool {
    std::env::var("SB_ACCESS_LOG")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn now_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0)
}

/// 打一行结构化访问日志（JSON），只有 SB_ACCESS_LOG=1 时生效。
        // - `event`：事件名，如 "http_connect_ok"、"socks_udp_forward"
        // - `kv`：若干键值对（自动转义），常见键：proto, client, target, decision, code, bytes
pub fn log(event: &str, kv: &[(&str, String)]) {
    if !enabled() {
        return;
    }
    let mut m = BTreeMap::new();
    m.insert("ts".to_string(), now_ms().to_string());
    m.insert("event".to_string(), event.to_string());
    for (k, v) in kv {
        m.insert((*k).to_string(), v.clone());
    }
    // 简单 JSON 序列化（无外部依赖）
    let mut out = String::with_capacity(128);
    out.push('{');
    let mut first = true;
    for (k, v) in m {
        if !first {
            out.push(',');
        }
        first = false;
        out.push('"');
        out.push_str(&escape(&k));
        out.push('"');
        out.push(':');
        out.push('"');
        out.push_str(&escape(&v));
        out.push('"');
    }
    out.push('}');
    eprintln!("{out}");
}

fn escape(s: &str) -> String {
    let mut t = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => t.push_str("\\\""),
            '\\' => t.push_str("\\\\"),
            '\n' => t.push_str("\\n"),
            '\r' => t.push_str("\\r"),
            '\t' => t.push_str("\\t"),
            c if c.is_control() => t.push_str(&format!("\\u{:04x}", c as u32)),
            c => t.push(c),
        }
    }
    t
}
