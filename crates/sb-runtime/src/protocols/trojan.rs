//! Trojan offline encode/ack (deterministic, placeholder implementation)
//!
//! Provides deterministic handshake test stub for Trojan protocol.
//! No real encryption, only for shape/length/reproducibility verification.
//! 提供 Trojan 协议的确定性握手测试桩。
//! 不做真实加密，仅用于 shape/长度/可复现性校验。

use crate::handshake::{derive_bytes, Handshake, ProtoCtx};
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Trojan Protocol Test Stub / Trojan 协议测试桩
///
/// Generates deterministic handshake messages for offline testing.
/// 生成确定性的握手消息，用于离线测试。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trojan {
    /// 协议上下文（主机和端口）
    pub ctx: ProtoCtx,
}

impl Trojan {
    /// 创建新的 Trojan 测试桩
    ///
    /// # 参数
    /// - `host`: 目标主机名或 IP
    /// - `port`: 目标端口
    #[must_use]
    pub fn new(host: String, port: u16) -> Self {
        Self {
            ctx: ProtoCtx { host, port },
        }
    }
}

impl Handshake for Trojan {
    fn encode_init(&self, seed: u64) -> Vec<u8> {
        // 伪结构：[LEN host][host bytes][port u16le][preface 16]
        let h = self.ctx.host.as_bytes();
        let mut out = Vec::with_capacity(1 + h.len() + 2 + 16);

        out.push(h.len() as u8);
        out.extend_from_slice(h);
        out.extend_from_slice(&self.ctx.port.to_le_bytes());
        out.extend_from_slice(&derive_bytes(seed ^ 0x5430_4A41, 16));

        out
    }

    fn decode_ack(&self, ack: &[u8]) -> Result<()> {
        // 仅校验长度 ≥ 8
        if ack.len() < 8 {
            anyhow::bail!("trojan ack too short (expected >= 8, got {})", ack.len());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_trojan_encode_deterministic() {
        let t = Trojan::new("example.com".to_string(), 443);
        let init1 = t.encode_init(42);
        let init2 = t.encode_init(42);
        assert_eq!(init1, init2, "encode_init should be deterministic");
    }

    #[test]
    fn test_trojan_decode_ack_valid() {
        let t = Trojan::new("example.com".to_string(), 443);
        let ack = vec![0_u8; 8];
        assert!(t.decode_ack(&ack).is_ok());
    }

    #[test]
    fn test_trojan_decode_ack_too_short() {
        let t = Trojan::new("example.com".to_string(), 443);
        let ack = vec![0_u8; 7];
        assert!(t.decode_ack(&ack).is_err());
    }
}
