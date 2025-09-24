//! Minimal HTTP/1.1 CONNECT inbound (scaffold).
//! - Optional Basic auth via (username,password)
//! - Route decision via Engine; outbound resolved by Bridge (adapter优先)
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use crate::adapter::Bridge;
use crate::adapter::InboundService;
use crate::log::Level;
use crate::routing::engine::{Engine, Input};

fn read_line(s: &mut TcpStream, buf: &mut Vec<u8>) -> std::io::Result<String> {
    buf.clear();
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
    let sline = String::from_utf8_lossy(buf).trim().to_string();
    Ok(sline)
}

fn read_headers(s: &mut TcpStream) -> std::io::Result<Vec<(String, String)>> {
    let mut h = Vec::new();
    let mut buf = Vec::with_capacity(256);
    loop {
        let line = read_line(s, &mut buf)?;
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            h.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok(h)
}

fn basic_ok(headers: &[(String, String)], user: &str, pass: &str) -> bool {
    use base64::Engine as _;
    let needle = format!("{}:{}", user, pass);
    let token = base64::engine::general_purpose::STANDARD.encode(needle.as_bytes());
    let expected = format!("Basic {}", token);
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("Proxy-Authorization") && v == &expected {
            return true;
        }
    }
    false
}

fn write_resp_line(s: &mut TcpStream, code: u16, text: &str) -> std::io::Result<()> {
    let body = format!("HTTP/1.1 {} {}\r\nContent-Length: 0\r\n\r\n", code, text);
    s.write_all(body.as_bytes())
}

fn copy_bidi(a: TcpStream, b: TcpStream) {
    let (mut ra, mut wa) = (a.try_clone().unwrap(), a);
    let (mut rb, mut wb) = (b.try_clone().unwrap(), b);
    let t1 = thread::spawn(move || {
        let _ = std::io::copy(&mut ra, &mut wb);
        let _ = wb.shutdown(Shutdown::Write);
    });
    let t2 = thread::spawn(move || {
        let _ = std::io::copy(&mut rb, &mut wa);
        let _ = wa.shutdown(Shutdown::Write);
    });
    let _ = t1.join();
    let _ = t2.join();
}

fn handle(
    mut cli: TcpStream,
    eng: &Engine,
    br: &Bridge,
    auth: Option<(&str, &str)>,
) -> std::io::Result<()> {
    // 1) 解析 Request-Line
    let mut buf = Vec::with_capacity(256);
    let line = read_line(&mut cli, &mut buf)?;
    // 仅支持：CONNECT host:port HTTP/1.1
    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let _ver = parts.next().unwrap_or("");
    if method != "CONNECT" || !target.contains(':') {
        write_resp_line(&mut cli, 405, "Method Not Allowed")?;
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "only CONNECT supported",
        ));
    }
    // 2) 解析头
    let headers = read_headers(&mut cli)?;
    // 3) 认证（可选）
    if let Some((u, p)) = auth {
        if !basic_ok(&headers, u, p) {
            let body = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"singbox\"\r\nContent-Length:0\r\n\r\n";
            let _ = cli.write_all(body.as_bytes());
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "proxy auth required",
            ));
        }
    }
    // 4) 路由决策
    let (host, port) = if let Some((h, p)) = target.rsplit_once(':') {
        (h.to_string(), p.parse::<u16>().unwrap_or(0))
    } else {
        (target.to_string(), 0)
    };
    let d = eng.decide(
        &Input {
            host: &host,
            port,
            network: "tcp",
            protocol: "http-connect",
        },
        false,
    );
    let out_name = d.outbound;
    let ob = br
        .find_outbound(&out_name)
        .or_else(|| br.find_direct_fallback());
    // 5) 建立上游连接
    match ob.as_ref().map(|x| x.connect(&host, port)).transpose() {
        Ok(up) => {
            write_resp_line(&mut cli, 200, "Connection Established")?;
            copy_bidi(cli, up.unwrap());
            Ok(())
        }
        Err(e) => {
            let _ = write_resp_line(&mut cli, 502, "Bad Gateway");
            Err(e)
        }
    }
}

#[derive(Debug)]
pub struct HttpConnect {
    listen: String,
    port: u16,
    engine: Option<Engine<'static>>,
    bridge: Option<std::sync::Arc<Bridge>>,
    basic_user: Option<String>,
    basic_pass: Option<String>,
}

impl HttpConnect {
    pub fn new(listen: String, port: u16) -> Self {
        Self {
            listen,
            port,
            engine: None,
            bridge: None,
            basic_user: None,
            basic_pass: None,
        }
    }
    pub fn with_engine(mut self, eng: Engine<'static>) -> Self {
        self.engine = Some(eng);
        self
    }
    pub fn with_bridge(mut self, br: std::sync::Arc<Bridge>) -> Self {
        self.bridge = Some(br);
        self
    }
    pub fn with_basic_auth(mut self, user: Option<String>, pass: Option<String>) -> Self {
        self.basic_user = user;
        self.basic_pass = pass;
        self
    }
    fn do_serve(&self, eng: Engine, br: std::sync::Arc<Bridge>) -> std::io::Result<()> {
        let addr = format!("{}:{}", self.listen, self.port);
        let l = TcpListener::bind(&addr)?;
        crate::log::log(Level::Info, "http-connect listening", &[("addr", &addr)]);
        for c in l.incoming() {
            match c {
                Ok(s) => {
                    let eng_owned = Engine::new(Box::leak(Box::new(eng.cfg.clone())));
                    let brc = br.clone();
                    let user = self.basic_user.clone();
                    let pass = self.basic_pass.clone();
                    thread::spawn(move || {
                        let auth = user.as_deref().zip(pass.as_deref());
                        let _ = handle(s, &eng_owned, &brc, auth);
                    });
                }
                Err(e) => {
                    crate::log::log(Level::Warn, "accept failed", &[("err", &format!("{}", e))]);
                    thread::sleep(Duration::from_millis(50));
                }
            }
        }
        Ok(())
    }
}

impl InboundService for HttpConnect {
    fn serve(&self) -> std::io::Result<()> {
        let cfg = sb_config::ir::ConfigIR::default();
        let eng = self.engine.clone().unwrap_or_else(|| Engine::new(&cfg));
        let br = self
            .bridge
            .clone()
            .unwrap_or_else(|| std::sync::Arc::new(Bridge::new()));
        self.do_serve(eng, br)
    }
}
