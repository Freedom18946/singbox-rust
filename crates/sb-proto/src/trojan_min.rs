//! R72: Trojan 最小握手构造器（纯字节，不做网络）
//! 请求格式（简化）：
//!   [password] CRLF
//!   CONNECT SP host ":" port CRLF
//!   CRLF
use bytes::{BufMut, BytesMut};

#[derive(Debug, Clone)]
pub struct TrojanHello {
    pub password: String,
    pub host: String,
    pub port: u16,
}

impl TrojanHello {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut b = BytesMut::with_capacity(self.password.len() + self.host.len() + 32);
        b.put(self.password.as_bytes());
        b.put(&b"\r\n"[..]);
        b.put(&b"CONNECT "[..]);
        b.put(self.host.as_bytes());
        b.put_u8(b':');
        b.put(self.port.to_string().as_bytes());
        b.put(&b"\r\n"[..]);
        b.put(&b"\r\n"[..]);
        b.to_vec()
    }
}
