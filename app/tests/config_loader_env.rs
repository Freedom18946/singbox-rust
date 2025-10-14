#![cfg(feature = "dev-cli")]

use sb_config::Config;
use std::fs;
use tempfile::NamedTempFile;

// 更新后的用例：直接构造配置，验证规则选择逻辑

#[test]
fn block_suffixes_blocks_example_com() {
    // 构造包含 Block 出站与规则的最小配置
    let json = r#"{
      "schema_version": 2,
      "inbounds": [],
      "outbounds": [
        {"type":"block","name":"block1"},
        {"type":"direct","name":"direct"}
      ],
      "rules": [
        {"domain_suffix":["example.com"], "outbound":"block1"}
      ],
      "default_outbound": "direct"
    }"#;

    // 写入临时文件并加载
    let tmp = NamedTempFile::new().expect("tmp");
    fs::write(tmp.path(), json).expect("write");
    let cfg = Config::load(tmp.path()).expect("load config");

    // 命中 example.com 后缀 → 选择 block1
    assert_eq!(cfg.pick_outbound_for_host("www.example.com"), Some("block1"));
    // 非命中 → 兜底 direct
    assert_eq!(cfg.pick_outbound_for_host("not-example.test"), None); // pick_outbound_for_host 只看规则；兜底由上层使用 default_outbound
}

#[test]
fn no_match_falls_back_to_default() {
    let json = r#"{
      "schema_version": 2,
      "inbounds": [],
      "outbounds": [
        {"type":"direct","name":"direct"}
      ],
      "rules": [
        {"domain_suffix":["never.match"], "outbound":"direct"}
      ],
      "default_outbound": "direct"
    }"#;

    let tmp = NamedTempFile::new().expect("tmp");
    fs::write(tmp.path(), json).expect("write");
    let cfg = Config::load(tmp.path()).expect("load config");

    // 未命中任何规则时，pick_outbound_for_host 返回 None；默认出站由运行时处理
    assert_eq!(cfg.pick_outbound_for_host("nonexistent.invalid"), None);
}
