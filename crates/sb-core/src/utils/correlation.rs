use std::fmt::{Display, Formatter};
use std::sync::atomic::{AtomicU64, Ordering};

static CID_SEQ: AtomicU64 = AtomicU64::new(1);

/// Correlation ID：简洁的 12 字节十六进制（高 48bit 时间戳秒 + 低 16bit 自增）
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct CorrelationId(u128);

impl CorrelationId {
    pub fn new() -> Self {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u128;
        let seq = (CID_SEQ.fetch_add(1, Ordering::Relaxed) & 0xFFFF) as u128;
        Self((ts << 16) | seq)
    }
}

impl Default for CorrelationId {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for CorrelationId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:012x}", self.0)
    }
}

/// 便捷函数：生成新 CID 的字符串
pub fn new_cid() -> String {
    CorrelationId::new().to_string()
}