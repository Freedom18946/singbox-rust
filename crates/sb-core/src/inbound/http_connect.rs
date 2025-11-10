//! Async HTTP/1.1 CONNECT inbound (scaffold).
//! - Optional Basic auth via (username,password)
//! - Route decision via Engine; outbound resolved by Bridge (adapter优先)
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

use crate::adapter::Bridge;
use crate::adapter::InboundService;
use crate::log::Level;
// Stage 2: HTTP Host sniff is inline; stream sniff stubs live in router::sniff

#[cfg(feature = "router")]
use crate::routing::engine::{Engine as RouterEngine, Input as RouterInput};

// Unified engine alias with lifetime for both router and stub modes
#[cfg(feature = "router")]
type EngineX<'a> = RouterEngine<'a>;
#[cfg(not(feature = "router"))]
type EngineX<'a> = Engine;

#[cfg(not(feature = "router"))]
#[derive(Debug)]
pub(crate) struct Engine {
    cfg: sb_config::ir::ConfigIR,
}

#[cfg(not(feature = "router"))]
struct Decision {
    outbound: String,
}

#[cfg(not(feature = "router"))]
impl Engine {
    fn new(cfg: sb_config::ir::ConfigIR) -> Self {
        Self { cfg }
    }

    fn decide(&self, _input: &Input, _fake_ip: bool) -> Decision {
        Decision {
            outbound: "direct".to_string(),
        }
    }
}

#[cfg(not(feature = "router"))]
impl Clone for Engine {
    fn clone(&self) -> Self {
        Self {
            cfg: self.cfg.clone(),
        }
    }
}

#[cfg(not(feature = "router"))]
#[allow(dead_code)]
struct Input {
    host: String,
    port: u16,
    network: String,
    protocol: String,
}

#[cfg(not(feature = "router"))]
impl Input {
    #[allow(dead_code)]
    fn new() -> Self {
        Self {
            host: String::new(),
            port: 0,
            network: String::new(),
            protocol: String::new(),
        }
    }
}

async fn read_headers(
    reader: &mut BufReader<&mut TcpStream>,
) -> std::io::Result<Vec<(String, String)>> {
    let mut headers = Vec::new();
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await?;
        let line = line.trim();
        if line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.push((k.trim().to_string(), v.trim().to_string()));
        }
    }
    Ok(headers)
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

pub(crate) async fn handle(
    mut cli: TcpStream,
    eng: &EngineX<'_>,
    br: &Bridge,
    auth: Option<(String, String)>,
    sniff_enabled: bool,
) -> std::io::Result<()> {
    let mut reader = BufReader::new(&mut cli);

    // 1) 解析 Request-Line
    let mut line = String::new();
    reader.read_line(&mut line).await?;
    let line = line.trim();

    let mut parts = line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");
    let _ver = parts.next().unwrap_or("");

    if method != "CONNECT" || !target.contains(':') {
        cli.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
            .await?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "only CONNECT supported",
            ));
    }

    // 2) 解析头
    let headers = read_headers(&mut reader).await?;

    // 3) 认证（可选）
    if let Some((u, p)) = auth.as_ref() {
        if !basic_ok(&headers, u, p) {
            let body = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"singbox\"\r\nContent-Length:0\r\n\r\n";
            cli.write_all(body).await?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "proxy auth required",
            ));
        }
    }

    // 4) 路由决策
    let (mut host, mut port) = if let Some((h, p)) = target.rsplit_once(':') {
        (h.to_string(), p.parse::<u16>().unwrap_or(0))
    } else {
        (target.to_string(), 0)
    };

    // Stage 2: HTTP Host sniff (prefer Host header if enabled)
    if sniff_enabled {
        if let Some((_k, v)) = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("Host"))
            .cloned()
        {
            // If Host header includes :port, prefer that port too
            if let Some((h, p)) = v.rsplit_once(':') {
                if let Ok(pp) = p.parse::<u16>() {
                    host = h.to_string();
                    port = if port == 0 { pp } else { port };
                } else {
                    host = v;
                }
            } else {
                host = v;
            }
        }
    }

    // Build route input and decide
    #[cfg(feature = "router")]
    let d = {
        let input = RouterInput {
            host: &host,
            port,
            network: "tcp",
            protocol: "http-connect",
            sniff_host: Some(&host),
            // For HTTP CONNECT control plane, we don't have stream bytes yet.
            // When sniff is enabled, we can still hint ALPN as http/1.1.
            sniff_alpn: if sniff_enabled { Some("http/1.1") } else { None },
        };
        eng.decide(&input, false)
    };
    #[cfg(not(feature = "router"))]
    let d = {
        let input = Input {
            host: host.clone(),
            port,
            network: "tcp".to_string(),
            protocol: "http-connect".to_string(),
        };
        eng.decide(&input, false)
    };
    let out_name = d.outbound;
    let ob = br
        .find_outbound(&out_name)
        .or_else(|| br.find_direct_fallback());

    // 5) 建立上游连接（异步）
    let mut upstream = match ob {
        Some(connector) => match connector.connect(&host, port).await {
            Ok(stream) => stream,
            Err(e) => {
                let _ = cli
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                    .await;
                return Err(std::io::Error::other(e));
            }
        },
        None => {
            let _ = cli
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
                .await;
            return Err(std::io::Error::other("no outbound connector available"));
        }
    };

    // 成功回包
    cli.write_all(b"HTTP/1.1 200 Connection Established\r\nContent-Length: 0\r\n\r\n")
        .await?;

    // 使用 tokio 的高性能双向复制
    let _ = tokio::io::copy_bidirectional(&mut cli, &mut upstream).await;

    Ok(())
}

#[derive(Debug)]
pub struct HttpConnect {
    listen: String,
    port: u16,
    #[cfg(feature = "router")]
    engine: Option<EngineX<'static>>,
    #[cfg(not(feature = "router"))]
    engine: Option<Engine>,
    bridge: Option<Arc<Bridge>>,
    basic_user: Option<String>,
    basic_pass: Option<String>,
    sniff_enabled: bool,
    shutdown: Arc<AtomicBool>,
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
            sniff_enabled: false,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    #[cfg(feature = "router")]
    pub fn with_engine(mut self, eng: EngineX<'static>) -> Self {
        self.engine = Some(eng);
        self
    }

    #[cfg(not(feature = "router"))]
    #[allow(dead_code)]
    pub(crate) fn with_engine(mut self, eng: Engine) -> Self {
        self.engine = Some(eng);
        self
    }

    pub fn with_bridge(mut self, br: Arc<Bridge>) -> Self {
        self.bridge = Some(br);
        self
    }

    /// Enable/disable inbound sniff features
    pub fn with_sniff(mut self, enabled: bool) -> Self {
        self.sniff_enabled = enabled;
        self
    }

    pub fn with_basic_auth(mut self, user: Option<String>, pass: Option<String>) -> Self {
        self.basic_user = user;
        self.basic_pass = pass;
        self
    }

    async fn do_serve_async(&self, eng: EngineX<'static>, br: Arc<Bridge>) -> std::io::Result<()> {
        let addr = format!("{}:{}", self.listen, self.port);
        let listener = TcpListener::bind(&addr).await?;
        crate::log::log(
            Level::Info,
            "http-connect listening (async)",
            &[("addr", &addr)],
        );

        loop {
            if self.shutdown.load(Ordering::Relaxed) { break; }
            match tokio::time::timeout(Duration::from_millis(1000), listener.accept()).await {
                Err(_) => continue,
                Ok(Err(e)) => {
                    crate::log::log(Level::Warn, "accept failed", &[("err", &format!("{}", e))]);
                    tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
                    continue;
                }
                Ok(Ok((socket, _))) => {
                    let eng_clone = eng.clone();
                    let br_clone = br.clone();
                    let auth = self.basic_user.clone().zip(self.basic_pass.clone());
                    let sniff = self.sniff_enabled;
                    tokio::spawn(async move {
                        if let Err(e) = handle(socket, &eng_clone, &br_clone, auth, sniff).await {
                            tracing::debug!(target: "sb_core::inbound::http_connect", error = %e, "connection handler failed");
                        }
                    });
                }
            }
        }
        Ok(())
    }
}

impl InboundService for HttpConnect {
    fn serve(&self) -> std::io::Result<()> {
        // 阻塞式入口，内部启动 tokio runtime
        #[cfg(not(feature = "router"))]
        let eng = {
            let cfg = sb_config::ir::ConfigIR::default();
            self.engine.clone().unwrap_or_else(|| EngineX::new(cfg))
        };

        #[cfg(feature = "router")]
        let eng = {
            // For router feature, use Box::leak for static lifetime
            let cfg = Box::leak(Box::new(sb_config::ir::ConfigIR::default()));
            self.engine.clone().unwrap_or_else(|| EngineX::new(cfg))
        };
        let br = self
            .bridge
            .clone()
            .unwrap_or_else(|| Arc::new(Bridge::new()));

        // 使用当前 tokio runtime 或创建新的
        match tokio::runtime::Handle::try_current() {
            Ok(handle) => {
                // Already in a tokio runtime
                handle.block_on(self.do_serve_async(eng, br))
            }
            Err(_) => {
                // No tokio runtime, create one
                let runtime = tokio::runtime::Runtime::new()
                    .map_err(std::io::Error::other)?;
                runtime.block_on(self.do_serve_async(eng, br))
            }
        }
    }

    fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }
}
