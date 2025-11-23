//! Mixed inbound: Detects SOCKS5 vs HTTP CONNECT and dispatches accordingly.
//! Minimal implementation using existing per-connection handlers.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};

use crate::adapter::{Bridge, InboundService};

#[cfg(feature = "router")]
use crate::routing::engine::Engine as RouterEngine;

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
impl Engine {
    fn new(cfg: sb_config::ir::ConfigIR) -> Self {
        Self { cfg }
    }
}

#[derive(Debug)]
pub struct MixedInbound {
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

impl MixedInbound {
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
    pub fn with_engine(mut self, eng: Engine) -> Self {
        self.engine = Some(eng);
        self
    }

    pub fn with_bridge(mut self, br: Arc<Bridge>) -> Self {
        self.bridge = Some(br);
        self
    }

    pub fn with_sniff(mut self, enabled: bool) -> Self {
        self.sniff_enabled = enabled;
        self
    }

    pub fn with_basic_auth(mut self, user: Option<String>, pass: Option<String>) -> Self {
        self.basic_user = user;
        self.basic_pass = pass;
        self
    }

    async fn serve_async(&self, eng: EngineX<'static>, br: Arc<Bridge>) -> std::io::Result<()> {
        let addr = format!("{}:{}", self.listen, self.port);
        let listener = TcpListener::bind(&addr).await?;
        tracing::info!(target = "sb_core::inbound::mixed", %addr, "mixed inbound listening");

        loop {
            if self.shutdown.load(Ordering::Relaxed) {
                break;
            }
            match tokio::time::timeout(Duration::from_millis(1000), listener.accept()).await {
                Err(_) => continue,
                Ok(Err(e)) => {
                    tracing::warn!(target = "sb_core::inbound::mixed", error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    continue;
                }
                Ok(Ok((socket, _))) => {
                    let eng_c = eng.clone();
                    let br_c = br.clone();
                    let auth = self.basic_user.clone().zip(self.basic_pass.clone());
                    let sniff = self.sniff_enabled;
                    tokio::spawn(async move {
                        if let Err(e) = handle_conn(socket, &eng_c, &br_c, auth, sniff).await {
                            tracing::debug!(target = "sb_core::inbound::mixed", error = %e, "connection failed");
                        }
                    });
                }
            }
        }
        Ok(())
    }
}

async fn handle_conn(
    cli: TcpStream,
    eng: &EngineX<'static>,
    br: &Bridge,
    http_auth: Option<(String, String)>,
    sniff_enabled: bool,
) -> std::io::Result<()> {
    // Peek first few bytes to detect protocol without consuming the stream
    let mut probe = [0u8; 8];
    let n = match cli.peek(&mut probe).await {
        Ok(n) => n,
        Err(e) => return Err(e),
    };
    if n > 0 && probe[0] == 0x05 {
        // SOCKS5
        return crate::inbound::socks5::handle_conn(cli, eng, br, sniff_enabled).await;
    }
    // Treat as HTTP CONNECT if starts with 'C' or fallback to HTTP
    return crate::inbound::http_connect::handle(cli, eng, br, http_auth, sniff_enabled).await;
}

impl InboundService for MixedInbound {
    fn serve(&self) -> std::io::Result<()> {
        #[cfg(not(feature = "router"))]
        let eng = {
            let cfg = sb_config::ir::ConfigIR::default();
            self.engine.clone().unwrap_or_else(|| EngineX::new(cfg))
        };
        #[cfg(feature = "router")]
        let eng = {
            let cfg = Box::leak(Box::new(sb_config::ir::ConfigIR::default()));
            self.engine.clone().unwrap_or_else(|| EngineX::new(cfg))
        };
        let br = self
            .bridge
            .clone()
            .unwrap_or_else(|| Arc::new(Bridge::new()));

        match tokio::runtime::Handle::try_current() {
            Ok(h) => h.block_on(self.serve_async(eng, br)),
            Err(_) => {
                let rt = tokio::runtime::Runtime::new().map_err(std::io::Error::other)?;
                rt.block_on(self.serve_async(eng, br))
            }
        }
    }

    fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }
}
