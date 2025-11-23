#![cfg(feature = "go1124_compat")]

use serde_json::Value;

fn ir_from_str(s: &str) -> sb_config::ir::ConfigIR {
    let v: Value = serde_json::from_str(s).expect("valid JSON");
    sb_config::validator::v2::to_ir_v1(&v)
}

fn strip_dns_rule_priority(mut ir: sb_config::ir::ConfigIR) -> sb_config::ir::ConfigIR {
    if let Some(dns) = &mut ir.dns {
        for r in &mut dns.rules {
            r.priority = None;
        }
    }
    ir
}

#[test]
fn golden_basic_ir_json_roundtrip() {
    let ir = ir_from_str(include_str!("golden/go1124/basic_input.json"));
    let json = serde_json::to_value(&ir).expect("serialize IR to JSON");
    let ir2 = sb_config::validator::v2::to_ir_v1(&json);
    let ir = strip_dns_rule_priority(ir);
    let ir2 = strip_dns_rule_priority(ir2);
    // For the basic sample, focus roundtrip assertions on DNS/NTP blocks,
    // which are the most parity-sensitive parts.
    assert_eq!(ir.dns, ir2.dns, "DNS block should roundtrip via to_ir_v1");
    assert_eq!(ir.ntp, ir2.ntp, "NTP block should roundtrip via to_ir_v1");
}

#[test]
fn golden_dns_address_https_rcode_ir_json_roundtrip() {
    let ir = ir_from_str(include_str!(
        "golden/go1124/dns_address_https_rcode_input.json"
    ));
    let json = serde_json::to_value(&ir).expect("serialize IR to JSON");
    let ir2 = sb_config::validator::v2::to_ir_v1(&json);
    let ir = strip_dns_rule_priority(ir);
    let ir2 = strip_dns_rule_priority(ir2);
    assert_eq!(
        ir, ir2,
        "dns_address_https_rcode IR JSON representation should roundtrip via to_ir_v1 (ignoring DNS rule priority)"
    );
}

#[test]
fn golden_dns_block_ref_ir_json_roundtrip() {
    let ir = ir_from_str(include_str!("golden/go1124/dns_block_ref_input.json"));
    let json = serde_json::to_value(&ir).expect("serialize IR to JSON");
    let ir2 = sb_config::validator::v2::to_ir_v1(&json);
    let ir = strip_dns_rule_priority(ir);
    let ir2 = strip_dns_rule_priority(ir2);
    assert_eq!(
        ir, ir2,
        "dns_block_ref IR JSON representation should roundtrip via to_ir_v1 (ignoring DNS rule priority)"
    );
}

#[test]
fn golden_dns_no_ref_keep_all_ir_json_roundtrip() {
    let ir = ir_from_str(include_str!("golden/go1124/dns_no_ref_keep_all_input.json"));
    let json = serde_json::to_value(&ir).expect("serialize IR to JSON");
    let ir2 = sb_config::validator::v2::to_ir_v1(&json);
    let ir = strip_dns_rule_priority(ir);
    let ir2 = strip_dns_rule_priority(ir2);
    assert_eq!(
        ir, ir2,
        "dns_no_ref_keep_all IR JSON representation should roundtrip via to_ir_v1 (ignoring DNS rule priority)"
    );
}

#[test]
fn golden_ntp_enabled_ir_json_roundtrip() {
    let ir = ir_from_str(include_str!("golden/go1124/ntp_enabled_input.json"));
    let json = serde_json::to_value(&ir).expect("serialize IR to JSON");
    let ir2 = sb_config::validator::v2::to_ir_v1(&json);
    let ir = strip_dns_rule_priority(ir);
    let ir2 = strip_dns_rule_priority(ir2);
    assert_eq!(
        ir, ir2,
        "ntp_enabled IR JSON representation should roundtrip via to_ir_v1 (ignoring DNS rule priority)"
    );
}
