//! SIP003 Plugin Protocol Implementation
//!
//! SIP003 is the Shadowsocks plugin protocol specification that allows
//! traffic obfuscation through external plugins.
//!
//! ## Protocol Overview
//!
//! The plugin acts as a local transport layer between the Shadowsocks client
//! and server, providing additional obfuscation.
//!
//! ```text
//! Client <-> SS-Local <-> Plugin <-> Network <-> Plugin <-> SS-Server <-> Target
//! ```
//!
//! ## Environment Variables
//!
//! Plugins receive configuration via environment variables:
//! - `SS_REMOTE_HOST` - Remote server address
//! - `SS_REMOTE_PORT` - Remote server port
//! - `SS_LOCAL_HOST` - Local bind address
//! - `SS_LOCAL_PORT` - Local bind port
//! - `SS_PLUGIN_OPTIONS` - Plugin-specific options
//!
//! ## References
//! - https://shadowsocks.org/guide/sip003.html

use std::collections::HashMap;
use std::io::{self, ErrorKind};
use std::net::SocketAddr;
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::sync::RwLock;

/// SIP003 plugin configuration
#[derive(Debug, Clone)]
pub struct Sip003Config {
    /// Plugin executable name or path
    pub plugin: String,
    /// Plugin options string (key=value;key2=value2 format)
    pub plugin_opts: Option<String>,
    /// Remote server address
    pub remote_addr: SocketAddr,
    /// Local bind address for plugin
    pub local_addr: SocketAddr,
}

impl Sip003Config {
    /// Create a new SIP003 configuration
    pub fn new(plugin: impl Into<String>, remote_addr: SocketAddr) -> Self {
        Self {
            plugin: plugin.into(),
            plugin_opts: None,
            remote_addr,
            local_addr: "127.0.0.1:0".parse().unwrap(),
        }
    }

    /// Set plugin options
    pub fn with_opts(mut self, opts: impl Into<String>) -> Self {
        self.plugin_opts = Some(opts.into());
        self
    }

    /// Set local bind address
    pub fn with_local_addr(mut self, addr: SocketAddr) -> Self {
        self.local_addr = addr;
        self
    }

    /// Parse plugin options into a HashMap
    pub fn parse_opts(&self) -> HashMap<String, String> {
        let mut opts = HashMap::new();
        if let Some(ref opts_str) = self.plugin_opts {
            for pair in opts_str.split(';') {
                if let Some((key, value)) = pair.split_once('=') {
                    opts.insert(key.trim().to_string(), value.trim().to_string());
                } else if !pair.trim().is_empty() {
                    // Flag without value
                    opts.insert(pair.trim().to_string(), String::new());
                }
            }
        }
        opts
    }

    /// Build environment variables for the plugin
    pub fn build_env(&self) -> Vec<(String, String)> {
        let mut env = vec![
            (
                "SS_REMOTE_HOST".to_string(),
                self.remote_addr.ip().to_string(),
            ),
            (
                "SS_REMOTE_PORT".to_string(),
                self.remote_addr.port().to_string(),
            ),
            (
                "SS_LOCAL_HOST".to_string(),
                self.local_addr.ip().to_string(),
            ),
            (
                "SS_LOCAL_PORT".to_string(),
                self.local_addr.port().to_string(),
            ),
        ];

        if let Some(ref opts) = self.plugin_opts {
            env.push(("SS_PLUGIN_OPTIONS".to_string(), opts.clone()));
        }

        env
    }
}

/// SIP003 plugin process manager
pub struct Sip003Plugin {
    config: Sip003Config,
    child: Option<Child>,
    actual_local_addr: Option<SocketAddr>,
}

impl Sip003Plugin {
    /// Create a new plugin manager
    pub fn new(config: Sip003Config) -> Self {
        Self {
            config,
            child: None,
            actual_local_addr: None,
        }
    }

    /// Start the plugin process
    pub async fn start(&mut self) -> io::Result<SocketAddr> {
        // Find an available port if not specified
        let listener = tokio::net::TcpListener::bind(&self.config.local_addr).await?;
        let local_addr = listener.local_addr()?;
        drop(listener);

        // Update config with actual port
        let mut config = self.config.clone();
        config.local_addr = local_addr;

        // Build command
        let mut cmd = Command::new(&config.plugin);

        // Set environment variables
        for (key, value) in config.build_env() {
            cmd.env(&key, &value);
        }

        // Configure process
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        tracing::info!(
            target: "sb_transport::sip003",
            plugin = %config.plugin,
            local = %local_addr,
            remote = %config.remote_addr,
            "Starting SIP003 plugin"
        );

        let child = cmd.spawn().map_err(|e| {
            io::Error::new(
                ErrorKind::Other,
                format!("Failed to start plugin '{}': {}", config.plugin, e),
            )
        })?;

        self.child = Some(child);
        self.actual_local_addr = Some(local_addr);

        // Give plugin time to start
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        Ok(local_addr)
    }

    /// Stop the plugin process
    pub async fn stop(&mut self) -> io::Result<()> {
        if let Some(mut child) = self.child.take() {
            tracing::info!(
                target: "sb_transport::sip003",
                plugin = %self.config.plugin,
                "Stopping SIP003 plugin"
            );
            child.kill().await?;
        }
        Ok(())
    }

    /// Check if plugin is running
    pub fn is_running(&mut self) -> bool {
        if let Some(ref mut child) = self.child {
            match child.try_wait() {
                Ok(None) => true,
                _ => false,
            }
        } else {
            false
        }
    }

    /// Get the local address the plugin is listening on
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.actual_local_addr
    }

    /// Connect through the plugin
    pub async fn connect(&self) -> io::Result<TcpStream> {
        let addr = self
            .actual_local_addr
            .ok_or_else(|| io::Error::new(ErrorKind::NotConnected, "Plugin not started"))?;

        TcpStream::connect(addr).await
    }
}

impl Drop for Sip003Plugin {
    fn drop(&mut self) {
        if let Some(ref mut child) = self.child {
            // Best effort kill
            let _ = child.start_kill();
        }
    }
}

/// SIP003 stream wrapper
pub struct Sip003Stream {
    inner: TcpStream,
    #[allow(dead_code)]
    plugin: Arc<RwLock<Sip003Plugin>>,
}

impl Sip003Stream {
    /// Create a new SIP003 stream by connecting through the plugin
    pub async fn connect(config: Sip003Config) -> io::Result<Self> {
        let mut plugin = Sip003Plugin::new(config);
        plugin.start().await?;

        let stream = plugin.connect().await?;

        Ok(Self {
            inner: stream,
            plugin: Arc::new(RwLock::new(plugin)),
        })
    }

    /// Get reference to the inner TCP stream
    pub fn inner(&self) -> &TcpStream {
        &self.inner
    }
}

impl AsyncRead for Sip003Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for Sip003Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Common SIP003 plugins
pub mod plugins {
    /// v2ray-plugin compatible modes
    pub mod v2ray {
        pub const MODE_WEBSOCKET: &str = "websocket";
        pub const MODE_QUIC: &str = "quic";

        /// Build v2ray-plugin options
        pub fn build_opts(mode: &str, host: &str, path: &str, tls: bool) -> String {
            let mut opts = format!("mode={}", mode);
            if !host.is_empty() {
                opts.push_str(&format!(";host={}", host));
            }
            if !path.is_empty() {
                opts.push_str(&format!(";path={}", path));
            }
            if tls {
                opts.push_str(";tls");
            }
            opts
        }
    }

    /// obfs-local plugin modes
    pub mod obfs {
        pub const MODE_HTTP: &str = "http";
        pub const MODE_TLS: &str = "tls";

        /// Build obfs-local options
        pub fn build_opts(mode: &str, host: &str) -> String {
            format!("obfs={};obfs-host={}", mode, host)
        }
    }

    /// kcptun plugin options
    pub mod kcptun {
        /// Build kcptun options
        pub fn build_opts(crypt: &str, key: &str, mode: &str, mtu: u16) -> String {
            format!("crypt={};key={};mode={};mtu={}", crypt, key, mode, mtu)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_parse_opts() {
        let config = Sip003Config::new("plugin", "1.2.3.4:8080".parse().unwrap())
            .with_opts("mode=websocket;host=example.com;tls");

        let opts = config.parse_opts();
        assert_eq!(opts.get("mode"), Some(&"websocket".to_string()));
        assert_eq!(opts.get("host"), Some(&"example.com".to_string()));
        assert_eq!(opts.get("tls"), Some(&String::new()));
    }

    #[test]
    fn test_build_env() {
        let config = Sip003Config::new("plugin", "1.2.3.4:8080".parse().unwrap())
            .with_local_addr("127.0.0.1:1080".parse().unwrap())
            .with_opts("test=value");

        let env = config.build_env();
        assert!(env
            .iter()
            .any(|(k, v)| k == "SS_REMOTE_HOST" && v == "1.2.3.4"));
        assert!(env
            .iter()
            .any(|(k, v)| k == "SS_REMOTE_PORT" && v == "8080"));
        assert!(env
            .iter()
            .any(|(k, v)| k == "SS_LOCAL_HOST" && v == "127.0.0.1"));
        assert!(env.iter().any(|(k, v)| k == "SS_LOCAL_PORT" && v == "1080"));
        assert!(env
            .iter()
            .any(|(k, v)| k == "SS_PLUGIN_OPTIONS" && v == "test=value"));
    }

    #[test]
    fn test_v2ray_plugin_opts() {
        let opts = plugins::v2ray::build_opts("websocket", "example.com", "/ws", true);
        assert_eq!(opts, "mode=websocket;host=example.com;path=/ws;tls");
    }

    #[test]
    fn test_obfs_plugin_opts() {
        let opts = plugins::obfs::build_opts("tls", "www.bing.com");
        assert_eq!(opts, "obfs=tls;obfs-host=www.bing.com");
    }
}
