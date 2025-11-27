//! VMess offline encode/ack (deterministic, placeholder implementation)
//!
//! Provides deterministic handshake test stub for VMess protocol.
//! No real encryption, only for shape/length/reproducibility verification.
//! 提供 VMess 协议的确定性握手测试桩。
//! 不做真实加密，仅用于 shape/长度/可复现性校验。

use crate::handshake::{derive_bytes, Handshake, ProtoCtx};
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// VMess Protocol Test Stub / VMess 协议测试桩
///
/// Generates deterministic handshake messages for offline testing.
/// 生成确定性的握手消息，用于离线测试。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vmess {
    /// 协议上下文（主机和端口）
    pub ctx: ProtoCtx,
}

impl Vmess {
    /// 创建新的 VMess 测试桩
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

impl Handshake for Vmess {
    fn encode_init(&self, seed: u64) -> Vec<u8> {
        // 伪结构：固定头 8B + 随机域 24B + hostlen/host + port
        let h = self.ctx.host.as_bytes();
        let mut out = Vec::with_capacity(8 + 24 + 1 + h.len() + 2);

        // 'VMESS\0\0\1'
        out.extend_from_slice(&[0x56, 0x4D, 0x45, 0x53, 0x53, 0, 0, 1]);
        out.extend_from_slice(&derive_bytes(seed ^ 0x5631_4535, 24));

        out.push(h.len() as u8);
        out.extend_from_slice(h);
        out.extend_from_slice(&self.ctx.port.to_le_bytes());

        out
    }

    fn decode_ack(&self, ack: &[u8]) -> Result<()> {
        // 校验长度 ≥ 12
        if ack.len() < 12 {
            anyhow::bail!("vmess ack too short (expected >= 12, got {})", ack.len());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vmess_encode_deterministic() {
        let v = Vmess::new("example.com".to_string(), 443);
        let init1 = v.encode_init(42);
        let init2 = v.encode_init(42);
        assert_eq!(init1, init2, "encode_init should be deterministic");
    }

    #[test]
    fn test_vmess_encode_has_magic() {
        let v = Vmess::new("example.com".to_string(), 443);
        let init = v.encode_init(42);
        // 检查 magic bytes 'VMESS'
        assert_eq!(&init[0..5], b"VMESS");
    }

    #[test]
    fn test_vmess_decode_ack_valid() {
        let v = Vmess::new("example.com".to_string(), 443);
        let ack = vec![0_u8; 12];
        assert!(v.decode_ack(&ack).is_ok());
    }

    #[test]
    fn test_vmess_decode_ack_too_short() {
        let v = Vmess::new("example.com".to_string(), 443);
        let ack = vec![0_u8; 11];
        assert!(v.decode_ack(&ack).is_err());
    }
}
