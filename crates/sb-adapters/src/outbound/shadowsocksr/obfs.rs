use anyhow::Result;
use bytes::{BufMut, BytesMut};
use rand::Rng;

/// Trait for ShadowsocksR obfuscation.
pub trait SsrObfs: Send + Sync {
    /// Obfuscate data (client -> server).
    fn encode(&mut self, data: &[u8], out: &mut BytesMut);

    /// De-obfuscate data (server -> client).
    fn decode(&mut self, data: &[u8], out: &mut BytesMut) -> Result<()>;

    /// Get overhead size.
    fn overhead(&self) -> usize;

    /// Get obfs name.
    fn name(&self) -> &'static str;
}

/// Obfs factory.
pub struct Obfs;

impl Obfs {
    /// Create an obfuscator by name.
    ///
    /// NOTE: ShadowsocksR is de-scoped (feature-gated OFF in Go reference).
    /// Only plain/none and http_simple are currently supported.
    pub fn create(name: &str, param: Option<&str>) -> Box<dyn SsrObfs> {
        match name.to_lowercase().as_str() {
            "plain" | "none" => Box::new(PlainObfs),
            "http_simple" => Box::new(HttpSimpleObfs::new(param)),
            _ => {
                tracing::warn!("Unsupported SSR obfs: {}, falling back to plain", name);
                Box::new(PlainObfs)
            }
        }
    }

    pub fn is_supported(name: &str) -> bool {
        matches!(
            name.to_lowercase().as_str(),
            "plain" | "none" | "http_simple"
        )
    }
}

/// Plain (no obfuscation).
pub struct PlainObfs;

impl SsrObfs for PlainObfs {
    fn encode(&mut self, data: &[u8], out: &mut BytesMut) {
        out.put_slice(data);
    }

    fn decode(&mut self, data: &[u8], out: &mut BytesMut) -> Result<()> {
        out.put_slice(data);
        Ok(())
    }

    fn overhead(&self) -> usize {
        0
    }

    fn name(&self) -> &'static str {
        "plain"
    }
}

/// HTTP Simple obfuscation.
pub struct HttpSimpleObfs {
    host: String,
    first_request: bool,
}

impl HttpSimpleObfs {
    pub fn new(param: Option<&str>) -> Self {
        Self {
            host: param.unwrap_or("bing.com").to_string(),
            first_request: true,
        }
    }

    fn generate_http_header(&self, data_len: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
        ];
        let ua = user_agents[rng.gen_range(0..user_agents.len())];

        // Use a persistent connection to mimic browser behavior
        format!(
            "GET / HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: {}\r\n\
             Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8\r\n\
             Accept-Language: en-US,en;q=0.5\r\n\
             Accept-Encoding: gzip, deflate\r\n\
             Connection: keep-alive\r\n\
             Content-Length: {}\r\n\
             \r\n",
            self.host, ua, data_len
        )
        .into_bytes()
    }
}

impl SsrObfs for HttpSimpleObfs {
    fn encode(&mut self, data: &[u8], out: &mut BytesMut) {
        if self.first_request && !data.is_empty() {
            let header = self.generate_http_header(data.len());
            out.reserve(header.len() + data.len());
            out.put_slice(&header);
            out.put_slice(data);
            self.first_request = false;
        } else {
            out.reserve(data.len());
            out.put_slice(data);
        }
    }

    fn decode(&mut self, data: &[u8], out: &mut BytesMut) -> Result<()> {
        // Simple heuristic: if it looks like HTTP response, strip headers
        // Look for double CRLF
        if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
            // Check if it starts with HTTP
            if data.starts_with(b"HTTP/") {
                // Strip header
                let payload = &data[pos + 4..];
                out.put_slice(payload);
                return Ok(());
            }
        }

        // Pass through if not recognized match
        out.put_slice(data);
        Ok(())
    }

    fn overhead(&self) -> usize {
        // Variable overhead, purely estimated for buffer resizing
        if self.first_request {
            512
        } else {
            0
        }
    }

    fn name(&self) -> &'static str {
        "http_simple"
    }
}
