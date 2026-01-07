use anyhow::Result;
use bytes::{BufMut, BytesMut};

/// Trait for ShadowsocksR ciphers.
pub trait SsrCipher: Send + Sync {
    /// Encrypt data.
    fn encrypt(&mut self, data: &[u8], out: &mut BytesMut);

    /// Decrypt data.
    fn decrypt(&mut self, data: &[u8], out: &mut BytesMut) -> Result<()>;

    /// Get cipher name.
    fn name(&self) -> &'static str;
}

/// Cipher factory.
pub struct Cipher;

impl Cipher {
    /// Create a cipher by method name.
    ///
    /// NOTE: ShadowsocksR is de-scoped (feature-gated OFF in Go reference).
    /// Only 'plain' cipher is implemented; other ciphers fall back to plain.
    pub fn create(method: &str, _password: &str) -> Box<dyn SsrCipher> {
        match method.to_lowercase().as_str() {
            "none" | "plain" => Box::new(PlainCipher),
            _ => {
                tracing::warn!("Unsupported SSR cipher: {}, falling back to plain", method);
                Box::new(PlainCipher)
            }
        }
    }
}

/// Plain (no encryption) cipher.
pub struct PlainCipher;

impl SsrCipher for PlainCipher {
    fn encrypt(&mut self, data: &[u8], out: &mut BytesMut) {
        out.put_slice(data);
    }

    fn decrypt(&mut self, data: &[u8], out: &mut BytesMut) -> Result<()> {
        out.put_slice(data);
        Ok(())
    }

    fn name(&self) -> &'static str {
        "plain"
    }
}
