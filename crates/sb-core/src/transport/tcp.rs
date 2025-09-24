//! TCP dial with timeout + metrics + classification.
use crate::errors::classify::{classify_io, NetClass};
use sb_metrics::registry::global as M;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct TcpDialer {
    pub connect_timeout: Duration,
    pub keepalive_secs: Option<u64>,
}

impl Default for TcpDialer {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(3),
            keepalive_secs: Some(30),
        }
    }
}

pub struct DialResult {
    pub stream: Option<TcpStream>,
    pub elapsed_ms: u128,
    pub error: Option<NetClass>,
}

impl TcpDialer {
    pub fn dial(&self, addr: &str) -> DialResult {
        let start = Instant::now();
        let to = self.connect_timeout;
        let r = (|| -> std::io::Result<TcpStream> {
            let mut last_err = None;
            for a in addr.to_socket_addrs()? {
                match TcpStream::connect_timeout(&a, to) {
                    Ok(s) => return Ok(s),
                    Err(e) => {
                        last_err = Some(e);
                    }
                }
            }
            Err(last_err.unwrap_or_else(|| std::io::Error::from(std::io::ErrorKind::Other)))
        })();
        let elapsed = start.elapsed().as_millis();
        match r {
            Ok(s) => {
                // Note: set_keepalive is not available in std::net::TcpStream
                // This would require socket2 crate for advanced socket options
                M().tcp_connect_duration.observe((elapsed as f64) / 1000.0);
                DialResult {
                    stream: Some(s),
                    elapsed_ms: elapsed,
                    error: None,
                }
            }
            Err(e) => {
                M().tcp_connect_duration.observe((elapsed as f64) / 1000.0);
                let c = classify_io(&e);
                DialResult {
                    stream: None,
                    elapsed_ms: elapsed,
                    error: Some(c),
                }
            }
        }
    }
}
