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
    pub fn create(name: &str, param: Option<&str>) -> Box<dyn SsrProtocol> {
        match name.to_lowercase().as_str() {
            "origin" | "plain" => Box::new(OriginProtocol),
            "auth_sha1_v4" => Box::new(AuthSha1V4Protocol::new(param)),
            // TODO: Implement other protocols (auth_aes128_md5, etc.)
            _ => {
                tracing::warn!("Unsupported SSR protocol: {}, falling back to origin", name);
                Box::new(OriginProtocol)
            }
        }
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

/// Auth SHA1 v4 protocol (stub).
pub struct AuthSha1V4Protocol {
    // TODO: Add state
}

impl AuthSha1V4Protocol {
    pub fn new(_param: Option<&str>) -> Self {
        Self {}
    }
}

impl SsrProtocol for AuthSha1V4Protocol {
    fn client_pre_encrypt(&mut self, data: &[u8], out: &mut BytesMut) {
        // TODO: Implement actual auth_sha1_v4 logic
        out.put_slice(data);
    }

    fn client_post_decrypt(&mut self, data: &[u8], out: &mut BytesMut) -> Result<()> {
        // TODO: Implement actual auth_sha1_v4 logic
        out.put_slice(data);
        Ok(())
    }

    fn overhead(&self) -> usize {
        7 // Stub overhead
    }

    fn name(&self) -> &'static str {
        "auth_sha1_v4"
    }
}
