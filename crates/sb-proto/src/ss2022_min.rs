//! R88: SS2022 最小握手构造器（纯字节，不做网络，feature=proto_ss2022_min）
//! 目标：给 admin dryrun 与单测使用，真实实现后再扩展
use bytes::{BufMut, BytesMut};

#[derive(Debug, Clone)]
pub struct Ss2022Hello {
    pub method: String, // e.g., "2022-blake3-aes-256-gcm"
    pub password: String,
    pub host: String,
    pub port: u16,
}

impl Ss2022Hello {
    /// 简化：组合一段可检测的"首包"标识 + 元信息（非协议线级正确性）
    pub fn to_bytes(&self) -> Vec<u8> {
        #[cfg(feature = "proto_ss2022_core")]
        {
            // 尝试使用 core 实现
            if let Some(aead) = crate::ss2022_core::parse_aead_kind(&self.method) {
                if let Ok(bytes) = crate::ss2022_core::build_client_first(
                    &self.method,
                    &self.password,
                    &self.host,
                    self.port,
                    aead,
                ) {
                    return bytes;
                }
            }
        }

        // Fallback: 原有实现
        let mut b =
            BytesMut::with_capacity(64 + self.host.len() + self.password.len() + self.method.len());
        b.put(&b"SS2022\0"[..]);
        b.put(self.method.as_bytes());
        b.put_u8(0);
        b.put(self.password.as_bytes());
        b.put_u8(0);
        b.put(self.host.as_bytes());
        b.put_u8(b':');
        b.put(self.port.to_string().as_bytes());
        b.to_vec()
    }
}
