mod credentials;
mod deprecation;
mod dns;
mod endpoint;
mod facade;
mod helpers;
mod inbound;
mod outbound;
mod route;
mod schema_core;
mod security;
mod service;
mod top_level;

use serde_json::Value;

// Re-export outbound TLS capability check for public API stability
pub use helpers::emit_issue;
pub use outbound::check_tls_capabilities;

pub(super) use helpers::{
    extract_listable_strings, extract_string_list, insert_keys, object_keys, parse_fwmark_field,
    parse_inbound_tls_options, parse_listable, parse_millis_field, parse_outbound_tls_options,
    parse_seconds_field_to_millis, parse_u16_field, parse_u32_field,
};

/// Lightweight schema validation: coordinates the v2 root, nested block,
/// deprecation, security, and TLS capability validators.
/// 轻量 schema 校验：编排 v2 根节点、嵌套块、弃用项、安全项与 TLS 能力检查。
///
/// # Arguments
/// * `doc` - The JSON document to validate / 待验证的 JSON 文档
/// * `allow_unknown` - Whether to treat unknown fields as warnings (true) instead of errors (false) / 是否将未知字段视为警告（true）而非错误（false）
pub fn validate_v2(doc: &serde_json::Value, allow_unknown: bool) -> Vec<Value> {
    facade::validate_v2(doc, allow_unknown)
}

/// Pack output.
/// 打包输出。
pub fn pack_output(issues: Vec<Value>) -> Value {
    facade::pack_output(issues)
}

/// Convert V1/V2 raw JSON to IR using the module-owned lowering pipeline.
/// 通过各模块负责的 lowering 流程将 v1/v2 原始 JSON 转 IR。
pub fn to_ir_v1(doc: &serde_json::Value) -> crate::ir::ConfigIR {
    facade::to_ir_v1(doc)
}
