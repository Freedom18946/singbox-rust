#[cfg(feature = "proto_ss2022_core")]
#[allow(clippy::module_inception)]
pub mod ss2022_core {
    use thiserror::Error;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum AeadKind {
        Aes256Gcm,
        Chacha20Poly1305,
    }

    #[derive(Error, Debug)]
    pub enum SS2022Error {
        #[error("Invalid password format")]
        InvalidPassword,
        #[error("Invalid method")]
        InvalidMethod,
        #[error("Buffer too small")]
        BufferTooSmall,
    }

    /// 占位 KDF 实现，仅用于测试字节形状，不做真实加密
    /// 注意：这是测试用占位实现，不具备加密安全性
    pub fn derive_subkey_b3(pass: &str, salt: &[u8]) -> [u8; 32] {
        // 简单组合 password + salt 做 blake3，仅测试字节形状
        let mut hasher = blake3::Hasher::new();
        hasher.update(pass.as_bytes());
        hasher.update(salt);
        let hash = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&hash.as_bytes()[..32]);
        key
    }

    /// 构建客户端首包，统一字节布局
    /// 注意：这是占位实现，不做真正 AEAD 加密
    pub fn build_client_first(
        method: &str,
        pass: &str,
        host: &str,
        port: u16,
        aead: AeadKind,
    ) -> Result<Vec<u8>, SS2022Error> {
        // 基础检查
        if pass.is_empty() || host.is_empty() {
            return Err(SS2022Error::InvalidPassword);
        }

        // 构造简单的帧结构：header_len(2) + header + payload_len(2) + payload
        let mut result = Vec::new();

        // 模拟 header：method + aead_kind
        let header = format!("{}:{:?}", method, aead);
        let header_bytes = header.as_bytes();
        result.extend_from_slice(&(header_bytes.len() as u16).to_be_bytes());
        result.extend_from_slice(header_bytes);

        // 模拟 payload：target address
        let payload = format!("{}:{}", host, port);
        let payload_bytes = payload.as_bytes();
        result.extend_from_slice(&(payload_bytes.len() as u16).to_be_bytes());
        result.extend_from_slice(payload_bytes);

        // 添加占位 salt (16 bytes)
        let salt = b"SS2022_TEST_SALT";
        result.extend_from_slice(salt);

        // 添加占位 tag (16 bytes)
        let tag = b"SS2022_TEST__TAG";
        result.extend_from_slice(tag);

        Ok(result)
    }

    /// 辅助函数：获取 AEAD 类型的标识字符串
    pub fn aead_kind_str(aead: AeadKind) -> &'static str {
        match aead {
            AeadKind::Aes256Gcm => "aes-256-gcm",
            AeadKind::Chacha20Poly1305 => "chacha20-poly1305",
        }
    }

    /// 辅助函数：从字符串解析 AEAD 类型
    pub fn parse_aead_kind(s: &str) -> Option<AeadKind> {
        match s.to_lowercase().as_str() {
            "aes-256-gcm" | "aes256gcm" => Some(AeadKind::Aes256Gcm),
            "chacha20-poly1305" | "chacha20poly1305" => Some(AeadKind::Chacha20Poly1305),
            _ => None,
        }
    }
}

#[cfg(feature = "proto_ss2022_core")]
pub use ss2022_core::*;
