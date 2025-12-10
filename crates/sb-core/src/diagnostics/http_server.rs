//! Debug HTTP server.
//!
//! Provides debug endpoints:
//! - `GET /debug/gc` - Trigger memory cleanup (returns 204)
//! - `GET /debug/memory` - Memory statistics JSON
//! - `GET /debug/pprof/*` - Profiling endpoints
//!
//! Mirrors Go's `debug_http.go`.

use super::memory::MemoryStats;
use super::options::DebugOptions;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tracing::{error, info, warn};

/// Debug HTTP server.
pub struct DebugServer {
    /// Listen address.
    addr: SocketAddr,
    /// Shutdown signal sender.
    shutdown_tx: Option<oneshot::Sender<()>>,
    /// Server task handle.
    handle: Option<tokio::task::JoinHandle<()>>,
}

impl DebugServer {
    /// Create and start a new debug server.
    pub async fn start(
        options: &DebugOptions,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let listen = options
            .listen
            .as_ref()
            .ok_or("Debug server listen address not configured")?;

        let addr: SocketAddr = listen
            .parse()
            .map_err(|e| format!("Invalid debug listen address '{}': {}", listen, e))?;

        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| format!("Failed to bind debug server to {}: {}", addr, e))?;

        let actual_addr = listener.local_addr()?;
        info!(addr = %actual_addr, "Starting debug HTTP server");

        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        let handle = tokio::spawn(Self::run_server(listener, shutdown_rx));

        Ok(Self {
            addr: actual_addr,
            shutdown_tx: Some(shutdown_tx),
            handle: Some(handle),
        })
    }

    /// Get the actual listen address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Shutdown the server.
    pub async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            let _ = handle.await;
        }
        info!("Debug HTTP server stopped");
    }

    /// Run the HTTP server.
    async fn run_server(listener: TcpListener, mut shutdown_rx: oneshot::Receiver<()>) {
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    break;
                }
                result = listener.accept() => {
                    match result {
                        Ok((stream, peer)) => {
                            tokio::spawn(Self::handle_connection(stream, peer));
                        }
                        Err(e) => {
                            error!(error = %e, "Failed to accept debug connection");
                        }
                    }
                }
            }
        }
    }

    /// Handle a single HTTP connection.
    async fn handle_connection(mut stream: tokio::net::TcpStream, peer: SocketAddr) {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let (reader, mut writer) = stream.split();
        let mut reader = BufReader::new(reader);

        // Read request line
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).await.is_err() {
            return;
        }

        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 2 {
            return;
        }

        let method = parts[0];
        let path = parts[1];

        // Skip remaining headers
        let mut line = String::new();
        loop {
            line.clear();
            if reader.read_line(&mut line).await.is_err() {
                return;
            }
            if line.trim().is_empty() {
                break;
            }
        }

        // Route request
        let response = match (method, path) {
            ("GET", "/debug/gc") => Self::handle_gc().await,
            ("GET", "/debug/memory") => Self::handle_memory().await,
            ("GET", path) if path.starts_with("/debug/pprof") => Self::handle_pprof(path).await,
            ("GET", "/debug") | ("GET", "/debug/") => Self::handle_index().await,
            _ => Self::not_found(),
        };

        // Write response
        if writer.write_all(response.as_bytes()).await.is_err() {
            warn!(peer = %peer, "Failed to write response");
        }
    }

    /// GET /debug - Index page.
    async fn handle_index() -> String {
        let html = r#"<!DOCTYPE html>
<html>
<head><title>Debug</title></head>
<body>
<h1>Debug Endpoints</h1>
<ul>
<li><a href="/debug/gc">/debug/gc</a> - Trigger memory cleanup</li>
<li><a href="/debug/memory">/debug/memory</a> - Memory statistics</li>
<li><a href="/debug/pprof/">/debug/pprof/</a> - Profiling (limited in Rust)</li>
</ul>
<p>Note: Rust has no GC, so /debug/gc is a no-op. Profiling requires additional setup.</p>
</body>
</html>"#;

        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\n\r\n{}",
            html.len(),
            html
        )
    }

    /// GET /debug/gc - Trigger garbage collection.
    ///
    /// In Rust, there's no GC. We just return 204 for compatibility.
    async fn handle_gc() -> String {
        // No-op in Rust - we don't have a GC
        // Could potentially call jemalloc purge if using jemalloc
        "HTTP/1.1 204 No Content\r\n\r\n".to_string()
    }

    /// GET /debug/memory - Memory statistics.
    async fn handle_memory() -> String {
        let stats = MemoryStats::collect();

        match serde_json::to_string_pretty(&stats) {
            Ok(json) => format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                json.len(),
                json
            ),
            Err(e) => format!(
                "HTTP/1.1 500 Internal Server Error\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
                e.to_string().len(),
                e
            ),
        }
    }

    /// GET /debug/pprof/* - Profiling endpoints.
    ///
    /// Note: Rust doesn't have built-in pprof. We provide info and links.
    async fn handle_pprof(path: &str) -> String {
        let msg = format!(
            r#"{{
  "note": "Rust does not have built-in pprof support",
  "path": "{}",
  "alternatives": [
    "Use DHAT or heaptrack for heap profiling",
    "Use perf or flamegraph for CPU profiling",
    "Enable debug symbols and use cargo-instruments on macOS",
    "Consider adding pprof-rs crate for sampling profiler"
  ],
  "env_vars": {{
    "RUST_BACKTRACE": "1 for stack traces",
    "RUST_LIB_BACKTRACE": "1 for library stack traces"
  }}
}}"#,
            path
        );

        format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            msg.len(),
            msg
        )
    }

    /// 404 Not Found response.
    fn not_found() -> String {
        let body = "Not Found";
        format!(
            "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )
    }
}

impl Drop for DebugServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        if let Some(handle) = self.handle.take() {
            handle.abort();
        }
    }
}

/// Apply debug options (called during startup).
pub fn apply_debug_options(options: &DebugOptions) {
    // Log Rust-specific notes for Go-only options
    if options.gc_percent.is_some() {
        warn!("debug.gc_percent is a Go-only option, ignored in Rust (no GC)");
    }
    if options.max_stack.is_some() {
        warn!("debug.max_stack is a Go-only option, ignored in Rust");
    }
    if options.max_threads.is_some() {
        warn!("debug.max_threads is a Go-only option (Tokio thread count is set at runtime init)");
    }
    if options.panic_on_fault.is_some() {
        warn!("debug.panic_on_fault is a Go-only option, ignored in Rust");
    }
    if options.trace_back.is_some() {
        info!("For Rust backtraces, set RUST_BACKTRACE=1 environment variable");
    }

    // Memory limit could be used for OOM handling
    if let Some(limit) = options.memory_limit {
        info!(limit_bytes = limit, "Memory limit configured");
        // Could integrate with custom allocator or OOM handler
    }

    if options.oom_killer.unwrap_or(false) {
        info!("OOM killer enabled");
        // Could set up signal handler or memory monitor
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_debug_server_start_stop() {
        let options = DebugOptions::with_listen("127.0.0.1:0");
        let server = DebugServer::start(&options).await.unwrap();

        let addr = server.addr();
        assert!(addr.port() > 0);

        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_memory_endpoint() {
        let options = DebugOptions::with_listen("127.0.0.1:0");
        let server = DebugServer::start(&options).await.unwrap();
        let addr = server.addr();

        // Make HTTP request
        let response = reqwest::get(format!("http://{}/debug/memory", addr))
            .await
            .unwrap();

        assert!(response.status().is_success());
        let body: serde_json::Value = response.json().await.unwrap();
        assert!(body.get("heap").is_some());
        assert!(body.get("rss").is_some());

        server.shutdown().await;
    }

    #[tokio::test]
    async fn test_gc_endpoint() {
        let options = DebugOptions::with_listen("127.0.0.1:0");
        let server = DebugServer::start(&options).await.unwrap();
        let addr = server.addr();

        let response = reqwest::get(format!("http://{}/debug/gc", addr))
            .await
            .unwrap();

        assert_eq!(response.status().as_u16(), 204);

        server.shutdown().await;
    }
}
