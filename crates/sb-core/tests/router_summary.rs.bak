use sb_core::router::router_snapshot_summary;

#[test]
fn snapshot_summary_contains_key_fields() {
    std::env::set_var("SB_ROUTER_RULES", "suffix:.x=proxy\ndefault=direct");
    let s = router_snapshot_summary();
    // JSON 或文本两种模式都包含 gen/checksum/sizes/footprint 关键字或字段
    assert!(s.contains("checksum") || s.contains("\"checksum_hex\""));
    assert!(s.contains("gen=") || s.contains("\"generation\""));
}
