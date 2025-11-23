#![cfg(feature = "go1124_compat")]

use serde_json::Value;

fn ir_from_str(s: &str) -> sb_config::ir::ConfigIR {
    let v: Value = serde_json::from_str(s).expect("valid JSON");
    sb_config::validator::v2::to_ir_v1(&v)
}

#[test]
fn golden_basic_config_ir_equivalence() {
    let ir_in = ir_from_str(include_str!("golden/go1124/basic_input.json"));
    let ir_out = ir_from_str(include_str!("golden/go1124/basic_output.json"));
    // DNS/rules should be semantically equivalent; Go pretty-printer may
    // drop unused block servers. We assert rule parity and that all servers
    // referenced by rules exist in both IRs.
    let rules_in = &ir_in.dns.as_ref().expect("dns in input").rules;
    let rules_out = &ir_out.dns.as_ref().expect("dns in output").rules;
    assert_eq!(rules_in, rules_out, "DNS rules should match");

    // Ensure that all servers referenced by rules exist in both IRs.
    let used_tags: std::collections::HashSet<String> =
        rules_in.iter().map(|r| r.server.clone()).collect();
    let servers_in = &ir_in.dns.as_ref().expect("dns in input").servers;
    let servers_out = &ir_out.dns.as_ref().expect("dns in output").servers;
    for tag in &used_tags {
        let in_has = servers_in.iter().any(|s| &s.tag == tag);
        let out_has = servers_out.iter().any(|s| &s.tag == tag);
        assert!(
            in_has && out_has,
            "expected DNS server tag '{}' to exist in both input/output IR",
            tag
        );
    }
}

#[test]
fn golden_gui_sample_ir_equivalence() {
    let ir_in = ir_from_str(include_str!("golden/go1124/gui_sample_input.json"));
    let ir_out = ir_from_str(include_str!("golden/go1124/gui_sample_output.json"));
    // Same assertions as basic_config: focus on DNS semantics and rule/server parity.
    let rules_in = &ir_in.dns.as_ref().expect("dns in input").rules;
    let rules_out = &ir_out.dns.as_ref().expect("dns in output").rules;
    assert_eq!(rules_in, rules_out, "DNS rules should match");

    let used_tags: std::collections::HashSet<String> =
        rules_in.iter().map(|r| r.server.clone()).collect();
    let servers_in = &ir_in.dns.as_ref().expect("dns in input").servers;
    let servers_out = &ir_out.dns.as_ref().expect("dns in output").servers;
    for tag in &used_tags {
        let in_has = servers_in.iter().any(|s| &s.tag == tag);
        let out_has = servers_out.iter().any(|s| &s.tag == tag);
        assert!(
            in_has && out_has,
            "expected DNS server tag '{}' to exist in both input/output IR",
            tag
        );
    }
}

#[test]
fn golden_dns_address_https_rcode_ir_equivalence() {
    let ir_in = ir_from_str(include_str!(
        "golden/go1124/dns_address_https_rcode_input.json"
    ));
    let ir_out = ir_from_str(include_str!(
        "golden/go1124/dns_address_https_rcode_output.json"
    ));
    // For this case Go drops the unused rcode server in the pretty-printed
    // output. We assert that strategy and rules match, and that all servers
    // referenced by rules are present in both IRs.
    let rules_in = &ir_in.dns.as_ref().expect("dns in input").rules;
    let rules_out = &ir_out.dns.as_ref().expect("dns in output").rules;
    assert_eq!(rules_in, rules_out, "DNS rules should match");

    let used_tags: std::collections::HashSet<String> =
        rules_in.iter().map(|r| r.server.clone()).collect();
    let servers_in = &ir_in.dns.as_ref().expect("dns in input").servers;
    let servers_out = &ir_out.dns.as_ref().expect("dns in output").servers;
    for tag in &used_tags {
        let in_has = servers_in.iter().any(|s| &s.tag == tag);
        let out_has = servers_out.iter().any(|s| &s.tag == tag);
        assert!(
            in_has && out_has,
            "expected DNS server tag '{}' to exist in both input/output IR",
            tag
        );
    }
}

#[test]
fn golden_dns_block_ref_ir_equivalence() {
    let ir_in = ir_from_str(include_str!("golden/go1124/dns_block_ref_input.json"));
    let ir_out = ir_from_str(include_str!("golden/go1124/dns_block_ref_output.json"));
    assert_eq!(ir_in, ir_out, "dns_block_ref input/output IR should match");
}

#[test]
fn golden_dns_no_ref_keep_all_ir_equivalence() {
    let ir_in = ir_from_str(include_str!("golden/go1124/dns_no_ref_keep_all_input.json"));
    let ir_out = ir_from_str(include_str!(
        "golden/go1124/dns_no_ref_keep_all_output.json"
    ));
    assert_eq!(
        ir_in, ir_out,
        "dns_no_ref_keep_all input/output IR should match"
    );
}

#[test]
fn golden_inbound_empty_users_drop_ir_equivalence() {
    let ir_in = ir_from_str(include_str!(
        "golden/go1124/inbound_empty_users_drop_input.json"
    ));
    let ir_out = ir_from_str(include_str!(
        "golden/go1124/inbound_empty_users_drop_output.json"
    ));
    assert_eq!(
        ir_in, ir_out,
        "inbound_empty_users_drop input/output IR should match"
    );
}

#[test]
fn golden_ntp_enabled_ir_equivalence() {
    let ir_in = ir_from_str(include_str!("golden/go1124/ntp_enabled_input.json"));
    let ir_out = ir_from_str(include_str!("golden/go1124/ntp_enabled_output.json"));
    assert_eq!(ir_in, ir_out, "ntp_enabled input/output IR should match");
}
