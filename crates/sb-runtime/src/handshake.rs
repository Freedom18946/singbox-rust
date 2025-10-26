//! Core handshake traits and deterministic helpers (offline-only).
//!
//! 仅用于 shape/长度/可复现性校验，不做真实加密或 IO。
//!
//! # 设计目标
//! - 提供确定性的握手模拟（基于 seed 的可重现性）
//! - 支持多种协议的握手接口抽象
//! - 离线测试和协议验证
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// 统一的握手接口（alpha）
///
/// 此 trait 定义了协议握手的两个关键阶段：
/// 1. 客户端初始化消息编码
/// 2. 服务端确认消息解码验证
///
/// # 实现要求
/// - `encode_init` 必须是确定性的（相同 seed 产生相同输出）
/// - `decode_ack` 只做结构/长度校验，不做真实解密
pub trait Handshake {
    /// 依据 proto 上下文与 seed 生成首发报文（deterministic）
    ///
    /// # 参数
    /// - `seed`: 用于生成确定性随机数据的种子
    ///
    /// # 返回
    /// 初始化握手消息的字节序列
    #[must_use]
    fn encode_init(&self, seed: u64) -> Vec<u8>;

    /// 校验并解析对端 ACK（这里仅做结构/长度校验）
    ///
    /// # 参数
    /// - `ack`: 服务端返回的确认消息
    ///
    /// # 错误
    /// 当消息格式不符合协议规范时返回错误
    fn decode_ack(&self, ack: &[u8]) -> Result<()>;
}

/// 伪混淆器接口（alpha）
///
/// 用于测试场景中的流量混淆模拟，不提供真实的加密保护。
pub trait Obfuscator {
    /// 对数据进行就地混淆/解混淆
    ///
    /// # 参数
    /// - `inout`: 需要处理的数据（原地修改）
    fn apply(&mut self, inout: &mut [u8]);
}

/// 统一输入（不含 IO）
///
/// 协议握手所需的基本上下文信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtoCtx {
    /// 目标主机名或 IP
    pub host: String,
    /// 目标端口
    pub port: u16,
}

/// 简单 xorshift64* PRNG（与 CLI 保持一致）
///
/// 这是一个快速的伪随机数生成器，用于测试场景。
/// **注意**：不适用于加密场景，仅用于确定性测试数据生成。
///
/// # 算法
/// 使用 xorshift64* 算法，周期为 2^64 - 1
#[inline]
#[must_use]
pub fn xorshift64star(mut x: u64) -> u64 {
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    x.wrapping_mul(0x2545_F491_4F6C_DD1D)
}

/// 从 seed 派生固定长度字节（用于占位字段）
///
/// 使用 `xorshift64star` PRNG 生成确定性的字节序列。
///
/// # 参数
/// - `seed`: 随机数种子
/// - `len`: 需要生成的字节数
///
/// # 返回
/// 长度为 `len` 的字节向量
///
/// # 性能
/// 预先计算所需迭代次数，避免循环中的重复长度检查
#[must_use]
pub fn derive_bytes(seed: u64, len: usize) -> Vec<u8> {
    if len == 0 {
        return Vec::new();
    }

    // 每次迭代生成 8 字节，预先计算所需迭代次数
    let iterations = len.div_ceil(8);
    let mut out = Vec::with_capacity(iterations * 8);
    let mut s = seed;

    for _ in 0..iterations {
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

    #[test]
    fn derive_bytes_zero_length() {
        let result = derive_bytes(123, 0);
        assert_eq!(result.len(), 0);
    }

    #[test]
    fn derive_bytes_exact_length() {
        let result = derive_bytes(123, 16);
        assert_eq!(result.len(), 16);
    }

    #[test]
    fn derive_bytes_non_multiple_of_eight() {
        let result = derive_bytes(456, 13);
        assert_eq!(result.len(), 13);
    }

    #[test]
    fn xorshift64star_non_zero() {
        // 确保非零输入不产生零输出（xorshift64* 保证）
        assert_ne!(xorshift64star(1), 0);
        assert_ne!(xorshift64star(42), 0);
    }

    #[test]
    fn xorshift64star_deterministic() {
        let seed = 12345_u64;
        assert_eq!(xorshift64star(seed), xorshift64star(seed));
    }
}
