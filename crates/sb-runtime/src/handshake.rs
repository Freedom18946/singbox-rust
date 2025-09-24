//! Core handshake traits and deterministic helpers (offline-only).
//! 仅用于 shape/长度/可复现性校验，不做真实加密或 IO。
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// 统一的握手接口（alpha）
pub trait Handshake {
    /// 依据 proto 上下文与 seed 生成首发报文（deterministic）
    fn encode_init(&self, seed: u64) -> Vec<u8>;
    /// 校验并解析对端 ACK（这里仅做结构/长度校验）
    fn decode_ack(&self, ack: &[u8]) -> Result<()>;
}

/// 伪混淆器接口（alpha）
pub trait Obfuscator {
    fn apply(&mut self, inout: &mut [u8]);
}

/// 统一输入（不含 IO）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtoCtx {
    pub host: String,
    pub port: u16,
}

/// 简单 xorshift64* PRNG（与 CLI 保持一致）
#[inline]
pub fn xorshift64star(mut x: u64) -> u64 {
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    x.wrapping_mul(0x2545F4914F6CDD1D)
}

/// 从 seed 派生固定长度字节（用于占位字段）
pub fn derive_bytes(seed: u64, len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len);
    let mut s = seed;
    while out.len() < len {
        s = xorshift64star(s);
        out.extend_from_slice(&s.to_le_bytes());
    }
    out.truncate(len);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn prng_is_deterministic() {
        assert_eq!(derive_bytes(42, 16), derive_bytes(42, 16));
    }
}
