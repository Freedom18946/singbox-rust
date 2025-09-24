//! VMess offline encode/ack（deterministic，占位实现）
use crate::handshake::{derive_bytes, Handshake, ProtoCtx};
use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Vmess {
    pub ctx: ProtoCtx,
}
impl Vmess {
    pub fn new(host: String, port: u16) -> Self {
        Self {
            ctx: ProtoCtx { host, port },
        }
    }
}
impl Handshake for Vmess {
    fn encode_init(&self, seed: u64) -> Vec<u8> {
        // 伪结构：固定头 8B + 随机域 24B + hostlen/host + port
        let mut out = Vec::new();
        out.extend_from_slice(&[0x56, 0x4D, 0x45, 0x53, 0x53, 0, 0, 1]); // 'VMESS\0\0\1'
        out.extend_from_slice(&derive_bytes(seed ^ 0x56314535, 24));
        let h = self.ctx.host.as_bytes();
        out.push(h.len() as u8);
        out.extend_from_slice(h);
        out.extend_from_slice(&self.ctx.port.to_le_bytes());
        out
    }
    fn decode_ack(&self, ack: &[u8]) -> Result<()> {
        if ack.len() < 12 {
            anyhow::bail!("vmess ack too short");
        }
        Ok(())
    }
}
