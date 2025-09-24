//! Trojan offline encode/ack（deterministic，占位实现）
use crate::handshake::{derive_bytes, Handshake, ProtoCtx};
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Trojan {
    pub ctx: ProtoCtx,
}
impl Trojan {
    pub fn new(host: String, port: u16) -> Self {
        Self {
            ctx: ProtoCtx { host, port },
        }
    }
}
impl Handshake for Trojan {
    fn encode_init(&self, seed: u64) -> Vec<u8> {
        // 伪结构：[LEN host][host bytes][port u16le][preface 16]
        let mut out = Vec::new();
        let h = self.ctx.host.as_bytes();
        out.push(h.len() as u8);
        out.extend_from_slice(h);
        out.extend_from_slice(&self.ctx.port.to_le_bytes());
        out.extend_from_slice(&derive_bytes(seed ^ 0x54304A41, 16));
        out
    }
    fn decode_ack(&self, ack: &[u8]) -> Result<()> {
        // 仅校长度≥8
        if ack.len() < 8 {
            anyhow::bail!("trojan ack too short");
        }
        Ok(())
    }
}
