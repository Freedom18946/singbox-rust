use anyhow::Result;
use bytes::{BufMut, BytesMut};
/// Trait for ShadowsocksR protocol.
pub trait SsrProtocol: Send + Sync {
    /// Pre-handshake (client -> server).
    fn client_pre_encrypt(&mut self, data: &[u8], out: &mut BytesMut);

    /// Post-handshake (client -> server).
    fn client_post_decrypt(&mut self, data: &[u8], out: &mut BytesMut) -> Result<()>;

    /// Get overhead size.
    fn overhead(&self) -> usize;

    /// Get protocol name.
    fn name(&self) -> &'static str;
}

/// Protocol factory.
pub struct Protocol;

impl Protocol {
    /// Create a protocol by name.
    ///
    /// NOTE: ShadowsocksR is de-scoped (feature-gated OFF in Go reference).
    /// Only origin/plain is currently supported.
    pub fn create(name: &str, param: Option<&str>) -> Box<dyn SsrProtocol> {
        let _ = param;
        match name.to_lowercase().as_str() {
            "origin" | "plain" => Box::new(OriginProtocol),
            _ => {
                tracing::warn!("Unsupported SSR protocol: {}, falling back to origin", name);
                Box::new(OriginProtocol)
            }
        }
    }

    pub fn is_supported(name: &str) -> bool {
        matches!(name.to_lowercase().as_str(), "origin" | "plain")
    }
}

/// Origin (no protocol overhead).
pub struct OriginProtocol;

impl SsrProtocol for OriginProtocol {
    fn client_pre_encrypt(&mut self, data: &[u8], out: &mut BytesMut) {
        out.put_slice(data);
    }

    fn client_post_decrypt(&mut self, data: &[u8], out: &mut BytesMut) -> Result<()> {
        out.put_slice(data);
        Ok(())
    }

    fn overhead(&self) -> usize {
        0
    }

    fn name(&self) -> &'static str {
        "origin"
    }
}
