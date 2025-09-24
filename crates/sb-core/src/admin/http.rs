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
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

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

fn read_line(s: &mut TcpStream) -> std::io::Result<String> {
    let mut buf = Vec::with_capacity(128);
    let mut b = [0u8; 1];
    let mut last_cr = false;
    loop {
        let n = s.read(&mut b)?;
        if n == 0 {
            return Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        }
        buf.push(b[0]);
        if last_cr && b[0] == b'\n' {
            break;
        }
        last_cr = b[0] == b'\r';
        if buf.len() > 8192 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "line too long",
            ));
        }
    }
    Ok(String::from_utf8_lossy(&buf).trim().to_string())
}

fn read_headers(s: &mut TcpStream) -> std::io::Result<Vec<(String, String)>> {
    let mut h = Vec::new();
    loop {
        let line = read_line(s)?;
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            h.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok(h)
}

fn read_body(s: &mut TcpStream, headers: &[(String, String)]) -> std::io::Result<Vec<u8>> {
    let mut len = 0usize;
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("Content-Length") {
            len = v.parse::<usize>().unwrap_or(0);
        }
    }
    let mut buf = vec![0u8; len];
    let mut off = 0usize;
    while off < len {
        let n = s.read(&mut buf[off..])?;
        if n == 0 {
            break;
        }
        off += n;
    }
    Ok(buf)
}

fn write_json(s: &mut TcpStream, code: u16, body: &str) -> std::io::Result<()> {
    let hdr = format!(
        "HTTP/1.1 {} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
        code,
        body.as_bytes().len()
    );
    s.write_all(hdr.as_bytes())?;
    s.write_all(body.as_bytes())
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
    let line = read_line(&mut cli)?;
    let (method, path, _ver) = parse_path(&line);
    let headers = read_headers(&mut cli)?;
    // security gate
    if let Ok(peer) = cli.peer_addr() {
        if !is_loopback_or_private(&peer) && admin_token.is_none() {
            return write_json(&mut cli, 403, r#"{"error":"forbidden"}"#);
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
            return write_json(&mut cli, 403, r#"{"error":"forbidden"}"#);
        }
    }
    match (method, path) {
        ("GET", "/healthz") => {
            let obj = serde_json::json!({
                "ok": true,
                "pid": std::process::id(),
                "fingerprint": env!("CARGO_PKG_VERSION")
            });
            write_json(&mut cli, 200, &serde_json::to_string(&obj).unwrap())
        }
        ("GET", "/outbounds") => {
            let items: Vec<_> = bridge
                .outbounds_snapshot()
                .into_iter()
                .map(|(n, k)| serde_json::json!({"name":n,"kind":k}))
                .collect();
            let obj = serde_json::json!({ "items": items });
            write_json(&mut cli, 200, &serde_json::to_string(&obj).unwrap())
        }
        ("POST", "/explain") => {
            let body = read_body(&mut cli, &headers)?;
            let v: serde_json::Value =
                serde_json::from_slice(&body).unwrap_or(serde_json::json!({}));
            let dest = v.get("dest").and_then(|x| x.as_str()).unwrap_or("");
            let network = v.get("network").and_then(|x| x.as_str()).unwrap_or("tcp");
            let protocol = v
                .get("protocol")
                .and_then(|x| x.as_str())
                .unwrap_or("admin");
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
            write_json(&mut cli, 200, &serde_json::to_string(&obj).unwrap())
        }
        ("POST", "/reload") => handle_reload(&mut cli, &headers, supervisor, rt_handle),
        _ => {
            let obj = r#"{"error":"not_found"}"#;
            write_json(&mut cli, 404, obj)
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
            return write_json(cli, 500, &serde_json::to_string(&error_obj).unwrap());
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
            return write_json(cli, 400, &serde_json::to_string(&error_obj).unwrap());
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
            return write_json(cli, 400, &serde_json::to_string(&error_obj).unwrap());
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
                    return write_json(cli, 400, &serde_json::to_string(&error_obj).unwrap());
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
                return write_json(cli, 400, &serde_json::to_string(&error_obj).unwrap());
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
        return write_json(cli, 400, &serde_json::to_string(&error_obj).unwrap());
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
            return write_json(cli, 400, &serde_json::to_string(&error_obj).unwrap());
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
            return write_json(cli, 500, &serde_json::to_string(&error_obj).unwrap());
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

    write_json(cli, 200, &serde_json::to_string(&success_obj).unwrap())
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
