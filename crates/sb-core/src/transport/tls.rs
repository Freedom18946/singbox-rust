//! TLS client with rustls 0.23; failure classification & metric.
use crate::errors::classify::{classify_tls, NetClass};
use crate::transport::tcp::{DialResult, TcpDialer};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use std::io::Write;
use std::sync::Arc;
use tokio::net::TcpStream;

#[derive(Default)]
pub struct TlsClient {
    pub dialer: TcpDialer,
    pub alpn: Vec<Vec<u8>>,
}

pub struct TlsResult {
    pub error: Option<NetClass>,
    pub negotiated_alpn: Option<String>,
}

fn default_root_store() -> RootCertStore {
    let mut store = RootCertStore::empty();
    // webpki roots（按需可换成 rustls-native-certs）
    store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    store
}

impl TlsClient {
    pub fn from_env() -> Self {
        Self::default()
    }

    #[cfg(feature = "tls_rustls")]
    pub async fn connect(
        &self,
        server_name: String,
        tcp_stream: TcpStream,
    ) -> anyhow::Result<tokio_rustls::client::TlsStream<TcpStream>> {
        use tokio_rustls::TlsConnector;

        let mut cfg = ClientConfig::builder()
            .with_root_certificates(default_root_store())
            .with_no_client_auth();
        if !self.alpn.is_empty() {
            cfg.alpn_protocols = self.alpn.clone();
        }
        let cfg = Arc::new(cfg);

        let connector = TlsConnector::from(cfg);
        let server_name = server_name
            .clone()
            .try_into()
            .map_err(|e| anyhow::anyhow!("Invalid server name: {e}"))?;

        let tls_stream = connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| anyhow::anyhow!("TLS connection failed: {e}"))?;

        Ok(tls_stream)
    }

    #[cfg(not(feature = "tls_rustls"))]
    pub async fn connect(
        &self,
        _server_name: String,
        _tcp_stream: TcpStream,
    ) -> anyhow::Result<()> {
        Err(anyhow::anyhow!("TLS support requires tls_rustls feature"))
    }

    pub fn handshake(&self, server_name: &str, addr: &str) -> TlsResult {
        let DialResult { stream, error, .. } = self.dialer.dial(addr);
        if let Some(e) = error {
            return TlsResult {
                error: Some(e),
                negotiated_alpn: None,
            };
        }
        let stream = if let Some(s) = stream { s } else {
            let fallback = error.unwrap_or(NetClass {
                code: crate::error_map::IssueCode::TlsHandshakeProtocol,
                class: "proto",
            });
            return TlsResult {
                error: Some(fallback),
                negotiated_alpn: None,
            };
        };

        let mut cfg = ClientConfig::builder()
            .with_root_certificates(default_root_store())
            .with_no_client_auth();
        if !self.alpn.is_empty() {
            cfg.alpn_protocols = self.alpn.clone();
        }
        let cfg = Arc::new(cfg);

        let sn = match ServerName::try_from(server_name.to_owned()) {
            Ok(s) => s,
            Err(_) => {
                return TlsResult {
                    error: Some(NetClass {
                        code: crate::error_map::IssueCode::TlsHandshakeProtocol,
                        class: "proto",
                    }),
                    negotiated_alpn: None,
                }
            }
        };
        let conn = match ClientConnection::new(cfg, sn) {
            Ok(c) => c,
            Err(e) => {
                let cl = classify_tls(&e);
                sb_metrics::inc_udp_fail(cl.class); // 占位：沿用 udp_fail_total 做演示计数
                return TlsResult {
                    error: Some(cl),
                    negotiated_alpn: None,
                };
            }
        };
        let mut tls = StreamOwned::new(conn, stream);

        // 执行握手（阻塞式简化）
        if let Err(e) = tls.flush() {
            let cl = crate::errors::classify::classify_io(&e);
            return TlsResult {
                error: Some(cl),
                negotiated_alpn: None,
            };
        }

        let alpn = tls
            .conn
            .alpn_protocol()
            .map(|b| String::from_utf8_lossy(b).to_string());
        TlsResult {
            error: None,
            negotiated_alpn: alpn,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn tls_protocol_error_without_server() {
        // 连接到一个不会说 TLS 的本地端口（通常 9/echo/空洞端口），
        // 因环境差异，使用 loopback 随机端口很难保证；此处仅调用握手接口验证编译路径。
        let c = TlsClient::default();
        let _ = c.handshake("example.com", "127.0.0.1:9");
    }
}
