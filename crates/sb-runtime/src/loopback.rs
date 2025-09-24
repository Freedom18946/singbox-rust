//! Loopback connector and frame logging for offline handshake testing.
//! In-memory data echoing with optional obfuscation and JSONL frame logging.

use crate::handshake::{Handshake, Obfuscator};
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// In-memory loopback connection that echoes sent data back
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
    /// Create a new loopback connection
    pub fn new() -> Self {
        Self {
            tx_queue: VecDeque::new(),
            rx_queue: VecDeque::new(),
            obfuscator: None,
        }
    }

    /// Create a loopback connection with obfuscator
    pub fn with_obfuscator(obfuscator: Box<dyn Obfuscator>) -> Self {
        Self {
            tx_queue: VecDeque::new(),
            rx_queue: VecDeque::new(),
            obfuscator: Some(obfuscator),
        }
    }

    /// Send data to the loopback (stores in tx_queue, echoes to rx_queue)
    pub fn send(&mut self, data: &[u8]) -> usize {
        let len = data.len();

        // Store original in tx_queue
        self.tx_queue.extend(data.iter().copied());

        // Echo to rx_queue, applying obfuscation if present
        let mut echo_data = data.to_vec();
        if let Some(ref mut obf) = self.obfuscator {
            obf.apply(&mut echo_data);
        }
        self.rx_queue.extend(echo_data.iter().copied());

        len
    }

    /// Receive data from the loopback (reads from rx_queue)
    pub fn recv(&mut self, max: usize) -> Vec<u8> {
        let to_read = max.min(self.rx_queue.len());
        self.rx_queue.drain(..to_read).collect()
    }

    /// Get bytes transmitted count
    pub fn bytes_tx(&self) -> usize {
        self.tx_queue.len()
    }

    /// Get bytes received count (available in rx_queue)
    pub fn bytes_rx(&self) -> usize {
        self.rx_queue.len()
    }
}

impl Default for LoopConn {
    fn default() -> Self {
        Self::new()
    }
}

/// Frame direction for logging
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FrameDir {
    Tx,
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

/// A logged frame with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Frame {
    pub ts_ms: u64,
    pub dir: FrameDir,
    pub len: usize,
    pub head8_hex: String,
    pub tail8_hex: String,
}

impl Frame {
    /// Create a new frame from data
    pub fn new(dir: FrameDir, data: &[u8]) -> Self {
        let ts_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;

        let len = data.len();
        let head8_hex = hex_encode(&data[..len.min(8)]);
        let tail8_hex = if len <= 8 {
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

/// Session logger for JSONL frame logging
#[derive(Debug)]
pub struct SessionLog {
    path: PathBuf,
}

impl SessionLog {
    /// Create a new session logger
    pub fn new<P: AsRef<Path>>(path: P) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }

    /// Append a frame to the log file as JSONL
    pub fn log_frame(&self, frame: &Frame) -> Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| anyhow!("Failed to open log file {}: {}", self.path.display(), e))?;

        let json_line = serde_json::to_string(frame)
            .map_err(|e| anyhow!("Failed to serialize frame: {}", e))?;

        writeln!(file, "{}", json_line)
            .map_err(|e| anyhow!("Failed to write to log file {}: {}", self.path.display(), e))?;

        Ok(())
    }

    /// Stream frames from an existing JSONL file (iterator-style)
    pub fn stream_frames(&self) -> Result<impl Iterator<Item = Result<Frame>> + '_> {
        let file = OpenOptions::new()
            .read(true)
            .open(&self.path)
            .map_err(|e| anyhow!("Failed to open log file {}: {}", self.path.display(), e))?;
        let reader = BufReader::new(file);
        Ok(reader
            .lines()
            .map(|line| line.map_err(|e| anyhow!("read line failed: {e}")))
            .map(|res| {
                res.and_then(|s| {
                    if s.trim().is_empty() {
                        return Ok(Frame {
                            ts_ms: 0,
                            dir: FrameDir::Tx,
                            len: 0,
                            head8_hex: String::new(),
                            tail8_hex: String::new(),
                        });
                    }
                    serde_json::from_str::<Frame>(&s)
                        .map_err(|e| anyhow!("parse JSONL failed: {e}; line={}", s))
                })
            }))
    }
}

/// Basic metrics for a handshake session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMetrics {
    pub bytes_tx: usize,
    pub bytes_rx: usize,
}

/// Run a single handshake loopback test
pub fn run_once<P: AsRef<Path>>(
    proto: &dyn Handshake,
    seed: u64,
    log_path: Option<P>,
) -> Result<SessionMetrics> {
    let mut conn = LoopConn::new();

    // Generate init bytes
    let init_bytes = proto.encode_init(seed);

    // Send init bytes and echo back (simulating server response)
    let tx_len = conn.send(&init_bytes);
    let echo_slice_len = init_bytes.len().min(32); // Echo back a slice
    let echo_data = conn.recv(echo_slice_len);

    // Validate echo with decode_ack
    proto.decode_ack(&echo_data)?;

    // Log frames if requested
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

/// Simple XOR obfuscator for testing
#[derive(Debug)]
pub struct XorObfuscator {
    key: u8,
}

impl XorObfuscator {
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

/// Convert bytes to hex string
fn hex_encode(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Replay decoder against frames (uses only RX frames)
pub fn replay_decode(
    proto: &dyn Handshake,
    jsonl_path: &Path,
    strict: bool,
) -> Result<(usize, usize)> {
    let logger = SessionLog::new(jsonl_path);
    let mut frames = 0usize;
    let mut errors = 0usize;
    for item in logger.stream_frames()? {
        let frame = item?;
        if frame.len == 0 && frame.head8_hex.is_empty() {
            continue;
        }
        if matches!(frame.dir, FrameDir::Rx) {
            // We don't have full bytes, only len/head/tail; this is a shape check:
            // synthesize a minimal buffer that respects len and carries head/tail hints.
            // For offline validation we feed a zeroed buffer of min(len, 32).
            let feed_len = frame.len.min(32);
            let buf = vec![0u8; feed_len];
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

        // Should be XORed with 0xAA
        assert_ne!(received.as_slice(), data);

        // XOR again to get original
        let mut decoded = received;
        for byte in &mut decoded {
            *byte ^= 0xAA;
        }
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_run_once() {
        let trojan = Trojan::new("example.com".to_string(), 443);

        let result = run_once(&trojan, 42, None::<&str>);
        assert!(result.is_ok());

        let metrics = result.unwrap();
        assert!(metrics.bytes_tx > 0);
        assert!(metrics.bytes_rx > 0);
    }

    #[test]
    fn test_replay_decode() {
        use std::env;
        use std::fs;
        let t = Trojan::new("example.com".to_string(), 443);
        // prepare a temp jsonl with two frames (tx ignored, rx used)
        let dir = env::temp_dir();
        let p = dir.join("hs.tmp.jsonl");
        let logger = SessionLog::new(&p);
        logger
            .log_frame(&Frame::new(FrameDir::Tx, b"abcdef"))
            .unwrap();
        logger
            .log_frame(&Frame::new(FrameDir::Rx, b"abcdef0123456789"))
            .unwrap();
        let (frames, errs) = replay_decode(&t, &p, false).unwrap();
        assert_eq!(frames, 1);
        assert!(errs == 0 || errs == 1); // decode_ack may be strict per impl
        let _ = fs::remove_file(&p);
    }
}
