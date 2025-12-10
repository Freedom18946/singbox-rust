use anyhow::Result;
use bytes::{BufMut, BytesMut};

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
    pub fn create(name: &str, param: Option<&str>) -> Box<dyn SsrObfs> {
        match name.to_lowercase().as_str() {
            "plain" | "none" => Box::new(PlainObfs),
            "http_simple" => Box::new(HttpSimpleObfs::new(param)),
            // TODO: Implement other obfs (tls1.2_ticket_auth, etc.)
            _ => {
                tracing::warn!("Unsupported SSR obfs: {}, falling back to plain", name);
                Box::new(PlainObfs)
            }
        }
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

/// HTTP Simple obfuscation (stub).
pub struct HttpSimpleObfs {
    _host: String,
}

impl HttpSimpleObfs {
    pub fn new(param: Option<&str>) -> Self {
        Self {
            _host: param.unwrap_or("bing.com").to_string(),
        }
    }
}

impl SsrObfs for HttpSimpleObfs {
    fn encode(&mut self, data: &[u8], out: &mut BytesMut) {
        // TODO: Implement actual HTTP header generation
        // For now, just pass through (stub)
        out.put_slice(data);
    }

    fn decode(&mut self, data: &[u8], out: &mut BytesMut) -> Result<()> {
        // TODO: Implement actual HTTP header parsing
        out.put_slice(data);
        Ok(())
    }

    fn overhead(&self) -> usize {
        0 // Placeholder
    }

    fn name(&self) -> &'static str {
        "http_simple"
    }
}
