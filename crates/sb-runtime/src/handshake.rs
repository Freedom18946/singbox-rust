//! Core handshake traits and deterministic helpers (offline-only).
//!
//! # Purpose / 目的
//!
//! Only used for shape/length/reproducibility verification, no real encryption or IO.
//! 仅用于 shape/长度/可复现性校验，不做真实加密或 IO。
//!
//! # Design Goals / 设计目标
//!
//! - **Deterministic Handshake Simulation**: Reproducibility based on seeds.
//! - **Protocol Abstraction**: Unified interface for different protocols.
//! - **Offline Verification**: Test without network.
//!
//! - **确定性握手模拟**: 基于 seed 的可重现性。
//! - **协议抽象**: 支持多种协议的握手接口抽象。
//! - **离线测试和协议验证**: 无需网络即可测试。
use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Unified Handshake Interface (Alpha) / 统一的握手接口（Alpha）
///
/// This trait defines the two key stages of a protocol handshake:
/// 1. Client initialization message encoding.
/// 2. Server acknowledgement message decoding and verification.
///
/// 此 trait 定义了协议握手的两个关键阶段：
/// 1. 客户端初始化消息编码。
/// 2. 服务端确认消息解码验证。
///
/// # Implementation Requirements / 实现要求
///
/// - `encode_init` MUST be deterministic (same seed produces same output).
/// - `decode_ack` SHOULD only verify structure/length, not real decryption.
///
/// - `encode_init` 必须是确定性的（相同 seed 产生相同输出）。
/// - `decode_ack` 只做结构/长度校验，不做真实解密。
pub trait Handshake {
    /// Generate initial packet based on proto context and seed (deterministic).
    /// 依据 proto 上下文与 seed 生成首发报文（deterministic）。
    ///
    /// # Arguments / 参数
    ///
    /// - `seed`: Seed for deterministic random data generation. / 用于生成确定性随机数据的种子。
    ///
    /// # Returns / 返回
    ///
    /// Byte sequence of the initialization handshake message.
    /// 初始化握手消息的字节序列。
    #[must_use]
    fn encode_init(&self, seed: u64) -> Vec<u8>;

    /// Verify and parse peer ACK (Structure/Length check only).
    /// 校验并解析对端 ACK（这里仅做结构/长度校验）。
    ///
    /// # Arguments / 参数
    ///
    /// - `ack`: Acknowledgement message returned by the server. / 服务端返回的确认消息。
    ///
    /// # Errors / 错误
    ///
    /// Returns error if message format does not match protocol specification.
    /// 当消息格式不符合协议规范时返回错误。
    fn decode_ack(&self, ack: &[u8]) -> Result<()>;
}

/// Pseudo-Obfuscator Interface (Alpha) / 伪混淆器接口（Alpha）
///
/// Used for traffic obfuscation simulation in test scenarios, providing NO real encryption protection.
/// 用于测试场景中的流量混淆模拟，不提供真实的加密保护。
pub trait Obfuscator {
    /// Obfuscate/De-obfuscate data in-place.
    /// 对数据进行就地混淆/解混淆。
    ///
    /// # Arguments / 参数
    ///
    /// - `inout`: Data to be processed (modified in-place). / 需要处理的数据（原地修改）。
    fn apply(&mut self, inout: &mut [u8]);
}

/// Unified Input (No IO) / 统一输入（不含 IO）
///
/// Basic context information required for protocol handshake.
/// 协议握手所需的基本上下文信息。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtoCtx {
    /// Target hostname or IP. / 目标主机名或 IP。
    pub host: String,
    /// Target port. / 目标端口。
    pub port: u16,
}

/// Simple xorshift64* PRNG (Consistent with CLI) / 简单 xorshift64* PRNG（与 CLI 保持一致）
///
/// This is a fast pseudo-random number generator for test scenarios.
/// **NOTE**: Not suitable for cryptographic scenarios, only for deterministic test data generation.
///
/// 这是一个快速的伪随机数生成器，用于测试场景。
/// **注意**：不适用于加密场景，仅用于确定性测试数据生成。
///
/// # Algorithm / 算法
///
/// Uses xorshift64* algorithm with a period of 2^64 - 1.
/// 使用 xorshift64* 算法，周期为 2^64 - 1。
#[inline]
#[must_use]
pub fn xorshift64star(mut x: u64) -> u64 {
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    x.wrapping_mul(0x2545_F491_4F6C_DD1D)
}

/// Derive fixed-length bytes from seed (for placeholder fields).
/// 从 seed 派生固定长度字节（用于占位字段）。
///
/// Uses `xorshift64star` PRNG to generate deterministic byte sequences.
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
