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
    parse_inbound_tls_options, parse_listable, parse_millis_field, parse_seconds_field_to_millis,
    parse_u16_field, parse_u32_field,
};

/// Lightweight schema validation (placeholder implementation): parses built-in schema, checks against field set for UnknownField/TypeMismatch/MissingRequired.
/// Note: To avoid heavy dependencies, minimal necessary logic is implemented here; can be switched to jsonschema crate later while keeping output structure unchanged.
/// 轻量 schema 校验（占位实现）：解析内置 schema，对照字段集做 UnknownField/TypeMismatch/MissingRequired
/// 说明：为了不引入庞大依赖，这里实现最小必要逻辑；后续可切换 jsonschema crate，保持输出结构不变。
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

/// Convert V1/V2 raw JSON to IR (excerpt; V1 unknown fields ignored but warning optional).
/// 将 v1/v2 原始 JSON 转 IR（节选；v1 未知字段忽略但告警可选）。
pub fn to_ir_v1(doc: &serde_json::Value) -> crate::ir::ConfigIR {
    facade::to_ir_v1(doc)
}
