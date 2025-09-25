//! Minimal blocking Admin HTTP server (opt-in).
//! Endpoints:
//!   GET  /healthz                      → 200 JSON {ok,pid,fingerprint}
//!   GET  /outbounds                    → 200 JSON [{name,kind}]
//!   POST /explain {"dest","network","protocol"} → 200 JSON {dest,outbound}
//!   POST /reload  {"config": <obj>|null, "path": <string>|null} → 200 JSON {event,ok,changed,fingerprint,t}
//! Security:
//!   - Loopback-only by default (10/172/192/127/::1 accepted).
//!   - If ADMIN_TOKEN/--admin-token is set, require header `X-Admin-Token: <token>`.
use serde_json;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use once_cell::sync::Lazy;

use crate::adapter::Bridge;
use crate::routing::engine::{Engine, Input};
use crate::runtime::supervisor::Supervisor;
use sb_config::ir::ConfigIR;
use tokio::runtime::Handle;

fn is_loopback_or_private(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || matches!(v4.octets(), [10, ..])
                || matches!(v4.octets(), [172, b, ..] if (16..=31).contains(&b))
                || matches!(v4.octets(), [192, 168, ..])
        }
        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xfe00) == 0xfc00, // fc00::/7 unique local
    }
}

struct Limits {
    max_header_bytes: usize,
    max_body_bytes: usize,
    first_byte_timeout: Duration,
    first_line_timeout: Duration,
    read_timeout: Duration,
    write_timeout: Duration,
    max_conn_per_ip: usize,
    max_rps_per_ip: usize,
}

fn env_usize(key: &str) -> Option<usize> {
    std::env::var(key).ok().and_then(|v| v.parse::<usize>().ok())
}
fn env_u64(key: &str) -> Option<u64> {
    std::env::var(key).ok().and_then(|v| v.parse::<u64>().ok())
}

fn limits() -> Limits {
    Limits {
        max_header_bytes: env_usize("SB_ADMIN_MAX_HEADER_BYTES").unwrap_or(64 * 1024),
        max_body_bytes: env_usize("SB_ADMIN_MAX_BODY_BYTES").unwrap_or(2 * 1024 * 1024),
        first_byte_timeout: Duration::from_millis(env_u64("SB_ADMIN_FIRSTBYTE_TIMEOUT_MS").unwrap_or(1500)),
        first_line_timeout: Duration::from_millis(env_u64("SB_ADMIN_FIRSTLINE_TIMEOUT_MS").unwrap_or(3000)),
        read_timeout: Duration::from_millis(env_u64("SB_ADMIN_READ_TIMEOUT_MS").unwrap_or(4000)),
        write_timeout: Duration::from_millis(env_u64("SB_ADMIN_WRITE_TIMEOUT_MS").unwrap_or(4000)),
        max_conn_per_ip: env_usize("SB_ADMIN_MAX_CONN_PER_IP").unwrap_or(8),
        max_rps_per_ip: env_usize("SB_ADMIN_MAX_RPS_PER_IP").unwrap_or(16),
    }
}

#[derive(Default, Clone)]
struct ClientStat {
    concurrent: usize,
    tokens: f64,
    last_refill: Instant,
}

static PER_IP: Lazy<Mutex<HashMap<IpAddr, ClientStat>>> = Lazy::new(|| Mutex::new(HashMap::new()));

fn rate_check(ip: IpAddr, lim: &Limits) -> bool {
    let mut m = match PER_IP.lock() {
        Ok(g) => g,
        Err(_) => return true, // on poison, don't block
    };
    let now = Instant::now();
    let ent = m.entry(ip).or_insert_with(|| ClientStat {
        concurrent: 0,
        tokens: lim.max_rps_per_ip as f64,
        last_refill: now,
    });
    // refill tokens (simple token bucket at 1 token per 1000/max_rps milliseconds)
    let elapsed = now.saturating_duration_since(ent.last_refill);
    let rate_per_sec = lim.max_rps_per_ip as f64;
    if rate_per_sec > 0.0 {
        let add = (elapsed.as_secs_f64()) * rate_per_sec;
        ent.tokens = (ent.tokens + add).min(rate_per_sec);
    }
    ent.last_refill = now;
    if ent.tokens >= 1.0 {
        ent.tokens -= 1.0;
        true
    } else {
        false
    }
}

struct ConnGuard {
    ip: IpAddr,
}
impl Drop for ConnGuard {
    fn drop(&mut self) {
        if let Ok(mut m) = PER_IP.lock() {
            if let Some(s) = m.get_mut(&self.ip) {
                s.concurrent = s.concurrent.saturating_sub(1);
            }
        }
    }
}

fn inc_concurrency(ip: IpAddr, lim: &Limits) -> Result<ConnGuard, ()> {
    let mut m = PER_IP.lock().map_err(|_| ())?;
    let s = m.entry(ip).or_insert_with(ClientStat::default);
    if s.concurrent >= lim.max_conn_per_ip {
        return Err(());
    }
    s.concurrent += 1;
    Ok(ConnGuard { ip })
}

fn read_line(s: &mut TcpStream, total_read: &mut usize) -> std::io::Result<String> {
    let lim = limits();
    let start = Instant::now();
    let mut buf = Vec::with_capacity(128);
    let mut b = [0u8; 1];
    let mut last_cr = false;

    // First byte timeout
    s.set_read_timeout(Some(lim.first_byte_timeout))?;
    let n = s.read(&mut b)?;
    if n == 0 {
        return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
    }
    buf.push(b[0]);
    *total_read += 1;
    if *total_read > lim.max_header_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "header too large",
        ));
    }
    last_cr = b[0] == b'\r';

    // Remaining line within first_line_timeout
    let deadline = start + lim.first_line_timeout;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "first line timeout",
            ));
        }
        let remain = deadline.saturating_duration_since(now);
        s.set_read_timeout(Some(remain))?;
        let n = s.read(&mut b)?;
        if n == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        buf.push(b[0]);
        *total_read += 1;
        if *total_read > lim.max_header_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "header too large",
            ));
        }
        if last_cr && b[0] == b'\n' {
            break;
        }
        last_cr = b[0] == b'\r';
    }
    Ok(String::from_utf8_lossy(&buf).trim().to_string())
}

fn read_headers(s: &mut TcpStream) -> std::io::Result<Vec<(String, String)>> {
    let lim = limits();
    let mut h = Vec::new();
    let mut total = 0usize;
    s.set_read_timeout(Some(lim.read_timeout))?;
    loop {
        let line = read_line(s, &mut total)?;
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            h.push((k.trim().to_string(), v.trim().to_string()));
        } else {
            // skip invalid line
        }
        if total > lim.max_header_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "header too large",
            ));
        }
    }
    Ok(h)
}

fn read_body(s: &mut TcpStream, headers: &[(String, String)]) -> std::io::Result<Vec<u8>> {
    let lim = limits();
    let mut len = 0usize;
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("Content-Length") {
            len = match v.parse::<usize>() {
                Ok(v) => v,
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "bad content-length",
                    ))
                }
            };
        }
    }
    if len > lim.max_body_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "request body too large",
        ));
    }
    s.set_read_timeout(Some(lim.read_timeout))?;
    let mut buf = vec![0u8; len];
    let mut off = 0usize;
    while off < len {
        let n = s.read(&mut buf[off..])?;
        if n == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        off += n;
    }
    Ok(buf)
}

fn write_json(s: &mut TcpStream, code: u16, body: &str) -> std::io::Result<()> {
    let lim = limits();
    s.set_write_timeout(Some(lim.write_timeout))?;
    let hdr = format!(
        "HTTP/1.1 {} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        code,
        body.as_bytes().len()
    );
    s.write_all(hdr.as_bytes())?;
    s.write_all(body.as_bytes())
}

fn json_err(kind: &str, detail: &str) -> String {
    match serde_json::to_string(&serde_json::json!({"error":kind, "detail":detail})) {
        Ok(s) => s,
        Err(_) => format!("{{\"error\":\"{}\",\"detail\":\"{}\"}}", kind, detail),
    }
}

fn parse_path(line: &str) -> (&str, &str, &str) {
    // "GET /path HTTP/1.1"
    let mut it = line.split_whitespace();
    let m = it.next().unwrap_or("");
    let p = it.next().unwrap_or("/");
    let v = it.next().unwrap_or("HTTP/1.1");
    (m, p, v)
}

fn handle(
    mut cli: TcpStream,
    engine: &Engine,
    bridge: &Bridge,
    admin_token: Option<&str>,
    supervisor: Option<&Arc<Supervisor>>,
    rt_handle: Option<&Handle>,
) -> std::io::Result<()> {
    let lim = limits();
    // Basic slowloris + timeout guard on first line
    let mut total_read = 0usize;
    let line = read_line(&mut cli, &mut total_read)?;
    let (method, path, _ver) = parse_path(&line);
    let headers = read_headers(&mut cli)?;
    // security gate
    let peer_opt = cli.peer_addr().ok();
    if let Some(peer) = peer_opt {
        // concurrency limiter
        match inc_concurrency(peer.ip(), &lim) {
            Ok(_g) => {
                // rate limit check
                if !rate_check(peer.ip(), &lim) {
                    let body = json_err("rate_limited", "too many requests");
                    let _ = write_json(&mut cli, 429, &body);
                    return Ok(());
                }
            }
            Err(_) => {
                let body = json_err("too_many_connections", "per-ip concurrency exceeded");
                let _ = write_json(&mut cli, 429, &body);
                return Ok(());
            }
        }
        if !is_loopback_or_private(&peer) && admin_token.is_none() {
            let body = json_err("forbidden", "token required for non-local access");
            return write_json(&mut cli, 403, &body);
        }
    }
    if let Some(tok) = admin_token {
        let mut ok = false;
        for (k, v) in &headers {
            if k.eq_ignore_ascii_case("X-Admin-Token") && v == tok {
                ok = true;
                break;
            }
        }
        if !ok {
            let body = json_err("forbidden", "invalid admin token");
            return write_json(&mut cli, 403, &body);
        }
    }
    match (method, path) {
        ("GET", "/healthz") => {
            let obj = serde_json::json!({
                "ok": true,
                "pid": std::process::id(),
                "fingerprint": env!("CARGO_PKG_VERSION")
            });
            let body = serde_json::to_string(&obj).unwrap_or_else(|_| "{}".into());
            write_json(&mut cli, 200, &body)
        }
        ("GET", "/outbounds") => {
            let items: Vec<_> = bridge
                .outbounds_snapshot()
                .into_iter()
                .map(|(n, k)| serde_json::json!({"name":n,"kind":k}))
                .collect();
            let obj = serde_json::json!({ "items": items });
            let body = serde_json::to_string(&obj).unwrap_or_else(|_| "{}".into());
            write_json(&mut cli, 200, &body)
        }
        ("POST", "/explain") => {
            let body = match read_body(&mut cli, &headers) {
                Ok(b) => b,
                Err(e) => {
                    let body = json_err("bad_request", &format!("{}", e));
                    let _ = write_json(&mut cli, 400, &body);
                    return Ok(());
                }
            };
            let v: serde_json::Value = serde_json::from_slice(&body).unwrap_or_else(|_| serde_json::json!({}));
            let dest = v.get("dest").and_then(|x| x.as_str()).unwrap_or("");
            let network = v.get("network").and_then(|x| x.as_str()).unwrap_or("tcp");
            let protocol = v.get("protocol").and_then(|x| x.as_str()).unwrap_or("admin");
            let (host, port) = if let Some((h, p)) = dest.rsplit_once(':') {
                (h.to_string(), p.parse::<u16>().unwrap_or(0))
            } else {
                (dest.to_string(), 0)
            };
            let d = engine.decide(
                &Input {
                    host: &host,
                    port,
                    network,
                    protocol,
                },
                false,
            );
            let obj = serde_json::json!({
                "dest": dest,
                "outbound": d.outbound
            });
            let body = serde_json::to_string(&obj).unwrap_or_else(|_| "{}".into());
            write_json(&mut cli, 200, &body)
        }
        ("POST", "/reload") => handle_reload(&mut cli, &headers, supervisor, rt_handle),
        _ => {
            let obj = json_err("not_found", "no such endpoint");
            write_json(&mut cli, 404, &obj)
        }
    }
}

/// Handle reload request
fn handle_reload(
    cli: &mut TcpStream,
    headers: &[(String, String)],
    supervisor: Option<&Arc<Supervisor>>,
    rt_handle: Option<&Handle>,
) -> std::io::Result<()> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // Check if supervisor is available
    let supervisor = match supervisor {
        Some(s) => s,
        None => {
            let error_obj = serde_json::json!({
                "event": "reload",
                "ok": false,
                "error": {
                    "code": "internal",
                    "message": "supervisor not available"
                },
                "fingerprint": env!("CARGO_PKG_VERSION"),
                "t": now
            });
            let body = serde_json::to_string(&error_obj).unwrap_or_else(|_| "{}".into());
            return write_json(cli, 500, &body);
        }
    };

    // Parse request body
    let body = match read_body(cli, headers) {
        Ok(b) => b,
        Err(_) => {
            let error_obj = serde_json::json!({
                "event": "reload",
                "ok": false,
                "error": {
                    "code": "bad_request",
                    "message": "failed to read request body"
                },
                "fingerprint": env!("CARGO_PKG_VERSION"),
                "t": now
            });
            let body = serde_json::to_string(&error_obj).unwrap_or_else(|_| "{}".into());
            return write_json(cli, 400, &body);
        }
    };

    let request: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(_) => {
            let error_obj = serde_json::json!({
                "event": "reload",
                "ok": false,
                "error": {
                    "code": "bad_request",
                    "message": "invalid JSON"
                },
                "fingerprint": env!("CARGO_PKG_VERSION"),
                "t": now
            });
            let body = serde_json::to_string(&error_obj).unwrap_or_else(|_| "{}".into());
            return write_json(cli, 400, &body);
        }
    };

    // Extract config or path
    let config_obj = request.get("config");
    let path_str = request.get("path").and_then(|v| v.as_str());

    let new_ir = if let Some(config) = config_obj {
        if config.is_null() {
            None
        } else {
            // Parse config object to ConfigIR
            match serde_json::from_value::<ConfigIR>(config.clone()) {
                Ok(ir) => Some(ir),
                Err(e) => {
                    let error_obj = serde_json::json!({
                        "event": "reload",
                        "ok": false,
                        "error": {
                            "code": "invalid_config",
                            "message": format!("config parse error: {}", e)
                        },
                        "fingerprint": env!("CARGO_PKG_VERSION"),
                        "t": now
                    });
                    return write_json(cli, 400, &serde_json::to_string(&error_obj).unwrap());
                }
            }
        }
    } else if let Some(path) = path_str {
        // Load config from file
        match std::fs::read_to_string(path) {
            Ok(content) => match serde_json::from_str::<ConfigIR>(&content) {
                Ok(ir) => Some(ir),
                Err(e) => {
                    let error_obj = serde_json::json!({
                        "event": "reload",
                        "ok": false,
                        "error": {
                            "code": "invalid_config",
                            "message": format!("file parse error: {}", e)
                        },
                        "fingerprint": env!("CARGO_PKG_VERSION"),
                        "t": now
                    });
                    let body = serde_json::to_string(&error_obj).unwrap_or_else(|_| "{}".into());
                    return write_json(cli, 400, &body);
                }
            },
            Err(e) => {
                let error_obj = serde_json::json!({
                    "event": "reload",
                    "ok": false,
                    "error": {
                        "code": "bad_request",
                        "message": format!("file read error: {}", e)
                    },
                    "fingerprint": env!("CARGO_PKG_VERSION"),
                    "t": now
                });
                let body = serde_json::to_string(&error_obj).unwrap_or_else(|_| "{}".into());
                return write_json(cli, 400, &body);
            }
        }
    } else {
        let error_obj = serde_json::json!({
            "event": "reload",
            "ok": false,
            "error": {
                "code": "bad_request",
                "message": "either config or path must be provided"
            },
            "fingerprint": env!("CARGO_PKG_VERSION"),
            "t": now
        });
        let body = serde_json::to_string(&error_obj).unwrap_or_else(|_| "{}".into());
        return write_json(cli, 400, &body);
    };

    let ir = match new_ir {
        Some(ir) => ir,
        None => {
            let error_obj = serde_json::json!({
                "event": "reload",
                "ok": false,
                "error": {
                    "code": "bad_request",
                    "message": "no valid configuration provided"
                },
                "fingerprint": env!("CARGO_PKG_VERSION"),
                "t": now
            });
            let body = serde_json::to_string(&error_obj).unwrap_or_else(|_| "{}".into());
            return write_json(cli, 400, &body);
        }
    };

    // 执行真正的 reload：用 tokio 运行时句柄在同步线程里阻塞执行
    let diff_result = match rt_handle {
        Some(h) => h.block_on(async { supervisor.reload(ir).await }),
        None => Err(anyhow::anyhow!("no runtime handle")).map_err(|e| e.into()),
    };

    let diff_result = match diff_result {
        Ok(diff) => diff,
        Err(e) => {
            let error_obj = serde_json::json!({
                "event": "reload",
                "ok": false,
                "error": {
                    "code": "internal",
                    "message": format!("reload failed: {}", e)
                },
                "fingerprint": env!("CARGO_PKG_VERSION"),
                "t": now
            });
            let body = serde_json::to_string(&error_obj).unwrap_or_else(|_| "{}".into());
            return write_json(cli, 500, &body);
        }
    };

    // Success response
    let success_obj = serde_json::json!({
        "event": "reload",
        "ok": true,
        "changed": {
            "inbounds": {
                "added": diff_result.inbounds.added,
                "removed": diff_result.inbounds.removed
            },
            "outbounds": {
                "added": diff_result.outbounds.added,
                "removed": diff_result.outbounds.removed
            },
            "rules": {
                "added": diff_result.rules.added,
                "removed": diff_result.rules.removed
            }
        },
        "fingerprint": env!("CARGO_PKG_VERSION"),
        "t": now,
        "notes": ""
    });

    let body = serde_json::to_string(&success_obj).unwrap_or_else(|_| "{}".into());
    write_json(cli, 200, &body)
}

pub fn spawn_admin(
    listen: &str,
    engine: Engine<'static>,
    bridge: Arc<Bridge>,
    admin_token: Option<String>,
    supervisor: Option<Arc<Supervisor>>,
    rt_handle: Option<Handle>,
) -> std::io::Result<thread::JoinHandle<()>> {
    let l = TcpListener::bind(listen)?;
    let addr = l
        .local_addr()
        .ok()
        .map(|a| a.to_string())
        .unwrap_or_else(|| listen.to_string());
    crate::log::log(
        crate::log::Level::Info,
        "admin http listening",
        &[("addr", &addr)],
    );
    let h = thread::spawn(move || {
        for c in l.incoming() {
            match c {
                Ok(s) => {
                    let _ = s.set_nodelay(true);
                    let eng = Engine::new(engine.cfg);
                    let brc = bridge.clone();
                    let tok = admin_token.clone();
                    let sup = supervisor.clone();
                    let rth = rt_handle.clone();
                    thread::spawn(move || {
                        let _ = handle(s, &eng, &brc, tok.as_deref(), sup.as_ref(), rth.as_ref());
                    });
                }
                Err(e) => {
                    crate::log::log(
                        crate::log::Level::Warn,
                        "admin accept failed",
                        &[("err", &format!("{}", e))],
                    );
                }
            }
        }
    });
    Ok(h)
}
