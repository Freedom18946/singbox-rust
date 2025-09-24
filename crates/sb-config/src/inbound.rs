use serde::Deserialize;
use serde_json::Value;

/// 供 app/tests 使用的简单枚举定义；后续可逐步细化 schema
#[derive(Debug, Clone, Deserialize)]
pub enum InboundDef {
    Http(Value),
    Socks(Value),
    Tun(Value),
}
