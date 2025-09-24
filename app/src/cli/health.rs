use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::Duration;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HealthSnapshot {
    pub ok: bool,
    pub admin: Option<String>,
    pub pid: Option<u32>,
    pub uptime_ms: Option<u64>,
    pub allow_net: Option<bool>,
    pub features: Option<Vec<String>>,
    pub supported_kinds_count: Option<u64>,
    #[serde(flatten)]
    pub extra: serde_json::Value,
}

#[derive(Serialize, Debug, Clone)]
pub struct HealthReport {
    pub tried: bool,
    pub target: Option<String>,
    pub status_line: Option<String>,
    pub snapshot: Option<HealthSnapshot>,
    pub error: Option<String>,
}

pub fn probe_from_portfile(portfile: Option<&Path>, timeout_ms: u64) -> HealthReport {
    let pf = portfile
        .map(|p| p.to_path_buf())
        .or_else(|| {
            let p = Path::new("/tmp/admin.port");
            if p.exists() { Some(p.to_path_buf()) } else { None }
        });
    let Some(path) = pf else {
        return HealthReport {
            tried: false, target: None, status_line: None, snapshot: None, error: None
        };
    };
    let Ok(port) = fs::read_to_string(&path) else {
        return HealthReport {
            tried: true, target: None, status_line: None, snapshot: None,
            error: Some(format!("failed to read portfile: {}", path.display()))
        };
    };
    let port = port.trim();
    let addr = format!("127.0.0.1:{port}");
    let target = format!("http://{addr}/__health");
    let mut rep = HealthReport {
        tried: true, target: Some(target.clone()), status_line: None, snapshot: None, error: None
    };
    match TcpStream::connect(addr.clone()) {
        Ok(mut stream) => {
            let _ = stream.set_read_timeout(Some(Duration::from_millis(timeout_ms)));
            let _ = stream.set_write_timeout(Some(Duration::from_millis(timeout_ms)));
            let req = format!(
                "GET /__health HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"
            );
            if let Err(e) = stream.write_all(req.as_bytes()) {
                rep.error = Some(format!("write error: {e}"));
                return rep;
            }
            let mut buf = Vec::new();
            if let Err(e) = stream.read_to_end(&mut buf) {
                rep.error = Some(format!("read error: {e}"));
                return rep;
            }
            let text = String::from_utf8_lossy(&buf);
            // 取首行状态 + JSON 体（简易解析）
            let mut lines = text.lines();
            rep.status_line = lines.next().map(|s| s.to_string());
            // 找到空行后面的 body
            if let Some(idx) = text.find("\r\n\r\n") {
                let body = &text[idx+4..];
                if let Ok(v) = serde_json::from_str::<serde_json::Value>(body) {
                    // 映射到 HealthSnapshot，但不强制字段存在
                    let snap = serde_json::from_value::<HealthSnapshot>(v.clone())
                        .unwrap_or(HealthSnapshot {
                            ok: false, admin: None, pid: None, uptime_ms: None,
                            allow_net: None, features: None, supported_kinds_count: None,
                            extra: v,
                        });
                    rep.snapshot = Some(snap);
                } else {
                    rep.error = Some("health body is not valid json".into());
                }
            } else {
                rep.error = Some("malformed http response".into());
            }
        }
        Err(e) => {
            rep.error = Some(format!("connect error: {e}"));
        }
    }
    rep
}