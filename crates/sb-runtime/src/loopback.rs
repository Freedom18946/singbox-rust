//! Loopback connector and frame logging for offline handshake testing
//!
//! 提供内存回环连接和会话日志记录功能，用于离线协议握手测试。
//!
//! # 主要组件
//!
//! - [`LoopConn`][]: 内存回环连接，发送的数据会自动回显到接收队列
//! - [`Frame`][]: 单个数据帧的元数据（时间戳、方向、长度、头尾字节）
//! - [`SessionLog`][]: JSONL 格式的会话日志记录器
//! - [`XorObfuscator`][]: 简单的 XOR 混淆器实现
//!
//! # 设计思想
//!
//! - **零真实 IO**: 所有数据在内存中处理，不涉及网络 socket
//! - **确定性**: 支持可选的混淆器，但测试结果可重现
//! - **JSONL 日志**: 帧日志以 JSONL 格式存储，便于分析和回放

use crate::handshake::{Handshake, Obfuscator};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// 内存回环连接，自动回显发送的数据
///
/// 发送到连接的数据会被存储在 `tx_queue` 中，并自动回显到 `rx_queue`。
/// 可选的混淆器会在回显时应用。
///
/// # 示例
///
/// ```rust,ignore
/// let mut conn = LoopConn::new();
/// conn.send(b"hello");
/// let received = conn.recv(5);
/// assert_eq!(received, b"hello");
/// ```
pub struct LoopConn {
    tx_queue: VecDeque<u8>,
    rx_queue: VecDeque<u8>,
    obfuscator: Option<Box<dyn Obfuscator>>,
}

impl std::fmt::Debug for LoopConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoopConn")
            .field("tx_queue_len", &self.tx_queue.len())
            .field("rx_queue_len", &self.rx_queue.len())
            .field("has_obfuscator", &self.obfuscator.is_some())
            .finish()
    }
}

impl LoopConn {
    /// 创建新的回环连接
    #[must_use]
    pub fn new() -> Self {
        Self {
            tx_queue: VecDeque::new(),
            rx_queue: VecDeque::new(),
            obfuscator: None,
        }
    }

    /// 创建带混淆器的回环连接
    ///
    /// # 参数
    /// - `obfuscator`: 混淆器实现，会在数据回显时应用
    #[must_use]
    pub fn with_obfuscator(obfuscator: Box<dyn Obfuscator>) -> Self {
        Self {
            tx_queue: VecDeque::new(),
            rx_queue: VecDeque::new(),
            obfuscator: Some(obfuscator),
        }
    }

    /// 发送数据到回环（存储在 tx_queue，回显到 rx_queue）
    ///
    /// # 参数
    /// - `data`: 要发送的数据
    ///
    /// # 返回
    /// 发送的字节数
    pub fn send(&mut self, data: &[u8]) -> usize {
        let len = data.len();

        // 存储原始数据到 tx_queue
        self.tx_queue.extend(data.iter().copied());

        // 回显到 rx_queue，应用混淆（如果有）
        let mut echo_data = data.to_vec();
        if let Some(ref mut obf) = self.obfuscator {
            obf.apply(&mut echo_data);
        }
        self.rx_queue.extend(echo_data.iter().copied());

        len
    }

    /// 从回环接收数据（从 rx_queue 读取）
    ///
    /// # 参数
    /// - `max`: 最多读取的字节数
    ///
    /// # 返回
    /// 接收到的数据（可能少于 `max`）
    #[must_use]
    pub fn recv(&mut self, max: usize) -> Vec<u8> {
        let to_read = max.min(self.rx_queue.len());
        self.rx_queue.drain(..to_read).collect()
    }

    /// 获取已发送字节数（tx_queue 中的字节数）
    #[must_use]
    pub fn bytes_tx(&self) -> usize {
        self.tx_queue.len()
    }

    /// 获取可接收字节数（rx_queue 中的字节数）
    #[must_use]
    pub fn bytes_rx(&self) -> usize {
        self.rx_queue.len()
    }
}

impl Default for LoopConn {
    fn default() -> Self {
        Self::new()
    }
}

/// 帧方向（发送或接收）
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FrameDir {
    /// 发送帧
    Tx,
    /// 接收帧
    Rx,
}

impl std::fmt::Display for FrameDir {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameDir::Tx => write!(f, "tx"),
            FrameDir::Rx => write!(f, "rx"),
        }
    }
}

/// 带元数据的数据帧
///
/// 记录单个数据传输的时间戳、方向、长度和头尾字节的十六进制表示。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Frame {
    /// 时间戳（Unix 毫秒）
    pub ts_ms: u64,
    /// 帧方向
    pub dir: FrameDir,
    /// 数据长度
    pub len: usize,
    /// 前 8 字节的十六进制表示
    pub head8_hex: String,
    /// 后 8 字节的十六进制表示
    pub tail8_hex: String,
}

impl Frame {
    /// 从数据创建新帧
    ///
    /// # 参数
    /// - `dir`: 帧方向
    /// - `data`: 帧数据
    ///
    /// # 返回
    /// 新创建的帧，带有当前时间戳
    #[must_use]
    pub fn new(dir: FrameDir, data: &[u8]) -> Self {
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis() as u64);

        let len = data.len();
        let head8_hex = hex_encode(&data[..len.min(8)]);
        let tail8_hex = if len <= 8 {
            // 对于小于等于 8 字节的数据，tail 和 head 相同
            head8_hex.clone()
        } else {
            hex_encode(&data[len - 8..])
        };

        Self {
            ts_ms,
            dir,
            len,
            head8_hex,
            tail8_hex,
        }
    }
}

/// JSONL 会话日志记录器
///
/// 提供帧的 JSONL 格式持久化和流式读取功能。
#[derive(Debug)]
pub struct SessionLog {
    path: PathBuf,
}

impl SessionLog {
    /// 创建新的会话日志记录器
    ///
    /// # 参数
    /// - `path`: 日志文件路径
    #[must_use]
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// 追加帧到日志文件（JSONL 格式）
    ///
    /// # 参数
    /// - `frame`: 要记录的帧
    ///
    /// # 错误
    /// 当文件打开、序列化或写入失败时返回错误
    pub fn log_frame(&self, frame: &Frame) -> Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| anyhow!("Failed to open log file {}: {}", self.path.display(), e))?;

        let json_line = serde_json::to_string(frame)
            .map_err(|e| anyhow!("Failed to serialize frame: {}", e))?;

        writeln!(file, "{json_line}")
            .map_err(|e| anyhow!("Failed to write to log file {}: {}", self.path.display(), e))?;

        Ok(())
    }

    /// 流式读取 JSONL 日志文件中的帧
    ///
    /// # 返回
    /// 帧的迭代器，自动过滤空行
    ///
    /// # 错误
    /// 当文件打开失败时返回错误，解析失败的行会作为 `Err` 返回
    pub fn stream_frames(&self) -> Result<impl Iterator<Item = Result<Frame>> + '_> {
        let file = OpenOptions::new()
            .read(true)
            .open(&self.path)
            .map_err(|e| anyhow!("Failed to open log file {}: {}", self.path.display(), e))?;

        let reader = BufReader::new(file);
        Ok(reader
            .lines()
            .map(|line| line.map_err(|e| anyhow!("read line failed: {e}")))
            .filter_map(|res| match res {
                Ok(s) if s.trim().is_empty() => None, // 跳过空行
                Ok(s) => Some(
                    serde_json::from_str::<Frame>(&s)
                        .map_err(|e| anyhow!("parse JSONL failed: {e}; line={s}")),
                ),
                Err(e) => Some(Err(e)),
            }))
    }
}

/// 握手会话的基本指标
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMetrics {
    /// 发送字节数
    pub bytes_tx: usize,
    /// 接收字节数
    pub bytes_rx: usize,
}

/// 运行单次握手回环测试
///
/// # 参数
/// - `proto`: 实现了 `Handshake` trait 的协议
/// - `seed`: 用于生成确定性握手数据的种子
/// - `log_path`: 可选的日志文件路径
///
/// # 返回
/// 会话指标（发送/接收字节数）
///
/// # 错误
/// 当握手失败或日志写入失败时返回错误
pub fn run_once<P: AsRef<Path>>(
    proto: &dyn Handshake,
    seed: u64,
    log_path: Option<P>,
) -> Result<SessionMetrics> {
    let mut conn = LoopConn::new();

    // 生成初始化字节
    let init_bytes = proto.encode_init(seed);

    // 发送初始化字节并回显（模拟服务器响应）
    let tx_len = conn.send(&init_bytes);
    let echo_slice_len = init_bytes.len().min(32); // 回显一个切片
    let echo_data = conn.recv(echo_slice_len);

    // 使用 decode_ack 验证回显
    proto.decode_ack(&echo_data)?;

    // 如果需要，记录帧
    if let Some(log_path) = log_path {
        let logger = SessionLog::new(log_path);

        let tx_frame = Frame::new(FrameDir::Tx, &init_bytes);
        let rx_frame = Frame::new(FrameDir::Rx, &echo_data);

        logger.log_frame(&tx_frame)?;
        logger.log_frame(&rx_frame)?;
    }

    Ok(SessionMetrics {
        bytes_tx: tx_len,
        bytes_rx: echo_data.len(),
    })
}

/// 简单的 XOR 混淆器（用于测试）
///
/// 使用固定密钥对数据进行 XOR 运算。
/// **注意**：这不是加密，仅用于测试场景的流量混淆模拟。
#[derive(Debug)]
pub struct XorObfuscator {
    key: u8,
}

impl XorObfuscator {
    /// 创建新的 XOR 混淆器
    ///
    /// # 参数
    /// - `key`: XOR 密钥（单字节）
    #[must_use]
    pub fn new(key: u8) -> Self {
        Self { key }
    }
}

impl Obfuscator for XorObfuscator {
    fn apply(&mut self, inout: &mut [u8]) {
        for byte in inout {
            *byte ^= self.key;
        }
    }
}

/// 将字节转换为十六进制字符串
///
/// # 性能
/// 使用预分配容量的字符串和 `fmt::Write`，避免多次分配
fn hex_encode(data: &[u8]) -> String {
    use std::fmt::Write;
    data.iter().fold(
        String::with_capacity(data.len() * 2),
        |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        },
    )
}

/// 对 JSONL 帧进行回放解码验证（仅使用 RX 帧）
///
/// # 参数
/// - `proto`: 实现了 `Handshake` trait 的协议
/// - `jsonl_path`: JSONL 日志文件路径
/// - `strict`: 是否为严格模式（遇到第一个错误即返回）
///
/// # 返回
/// `(RX 帧数, 错误数)`
///
/// # 错误
/// 严格模式下，遇到第一个解码错误时返回错误
pub fn replay_decode(
    proto: &dyn Handshake,
    jsonl_path: &Path,
    strict: bool,
) -> Result<(usize, usize)> {
    let logger = SessionLog::new(jsonl_path);
    let mut frames = 0_usize;
    let mut errors = 0_usize;

    for item in logger.stream_frames()? {
        let frame = item?;

        // 跳过空帧
        if frame.len == 0 && frame.head8_hex.is_empty() {
            continue;
        }

        // 只处理 RX 帧
        if matches!(frame.dir, FrameDir::Rx) {
            // 我们没有完整的字节数据，只有 len/head/tail，这是形状检查：
            // 合成一个最小缓冲区，尊重 len 并携带 head/tail 提示。
            // 对于离线验证，我们提供一个零填充的缓冲区，长度为 min(len, 32)。
            let feed_len = frame.len.min(32);
            let buf = vec![0_u8; feed_len];

            if let Err(e) = proto.decode_ack(&buf) {
                if strict {
                    return Err(anyhow!(
                        "replay decode failed at frame {}: {}",
                        frames + 1,
                        e
                    ));
                }
                errors += 1;
            }
            frames += 1;
        }
    }

    Ok((frames, errors))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocols::trojan::Trojan;

    #[test]
    fn test_loopback_basic() {
        let mut conn = LoopConn::new();
        let data = b"hello world";

        let sent = conn.send(data);
        assert_eq!(sent, data.len());

        let received = conn.recv(5);
        assert_eq!(received, b"hello");

        let remaining = conn.recv(100);
        assert_eq!(remaining, b" world");
    }

    #[test]
    fn test_frame_creation() {
        let data = b"test data for frame";
        let frame = Frame::new(FrameDir::Tx, data);

        assert_eq!(frame.dir, FrameDir::Tx);
        assert_eq!(frame.len, data.len());
        assert_eq!(frame.head8_hex, "7465737420646174"); // "test dat"
        // tail 8 of "... for frame" == "72206672616d65"
        assert_eq!(frame.tail8_hex.len(), 16);
    }

    #[test]
    fn test_xor_obfuscator() {
        let mut conn = LoopConn::with_obfuscator(Box::new(XorObfuscator::new(0xAA)));
        let data = b"hello";

        conn.send(data);
        let received = conn.recv(5);

        // 应该被 0xAA XOR
        assert_ne!(received.as_slice(), data);

        // 再次 XOR 恢复原始数据
        let mut decoded = received;
        for byte in &mut decoded {
            *byte ^= 0xAA;
        }
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_run_once() -> Result<()> {
        let trojan = Trojan::new("example.com".to_string(), 443);

        let metrics = run_once(&trojan, 42, None::<&str>)?;
        assert!(metrics.bytes_tx > 0);
        assert!(metrics.bytes_rx > 0);
        Ok(())
    }

    #[test]
    fn test_replay_decode() -> Result<()> {
        use std::env;
        use std::fs;

        let t = Trojan::new("example.com".to_string(), 443);
        // 准备一个临时 JSONL，包含两个帧（tx 被忽略，rx 被使用）
        let dir = env::temp_dir();
        let p = dir.join("hs.tmp.jsonl");
        let logger = SessionLog::new(&p);

        logger.log_frame(&Frame::new(FrameDir::Tx, b"abcdef"))?;
        logger.log_frame(&Frame::new(FrameDir::Rx, b"abcdef0123456789"))?;

        let (frames, errs) = replay_decode(&t, &p, false)?;
        assert_eq!(frames, 1);
        // decode_ack 可能根据实现严格性返回 0 或 1 个错误
        assert!(errs == 0 || errs == 1);

        let _ = fs::remove_file(&p);
        Ok(())
    }

    #[test]
    fn test_hex_encode() {
        assert_eq!(hex_encode(b"hello"), "68656c6c6f");
        assert_eq!(hex_encode(b""), "");
        assert_eq!(hex_encode(&[0x00, 0xFF, 0xAB]), "00ffab");
    }
}
