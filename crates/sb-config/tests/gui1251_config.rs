use serde_json::{json, Value};

use sb_config::ir::{InboundType, RuleAction};

fn parse_fixture(source: &str) -> Value {
    serde_json::from_str(source).expect("fixture JSON must be valid")
}

fn load_production(raw: Value) -> (sb_config::Config, sb_config::ir::ConfigIR) {
    sb_config::config_from_raw_value(raw).expect("fixture must pass production config load path")
}

fn assert_load_error_contains(raw: Value, expected: &str) {
    let err = sb_config::config_from_raw_value(raw)
        .expect_err("config should fail strict production validation")
        .to_string();
    assert!(
        err.contains(expected),
        "expected error to contain {expected:?}, got {err:?}"
    );
}

#[test]
fn gui1251_fixtures_pass_production_load_path_without_schema_version() {
    let fixtures = [
        (
            "default_mixed_tun_disabled",
            include_str!("golden/gui1251/default_mixed_tun_disabled.json"),
            false,
        ),
        (
            "tun_system",
            include_str!("golden/gui1251/tun_system.json"),
            true,
        ),
        (
            "tun_gvisor",
            include_str!("golden/gui1251/tun_gvisor.json"),
            true,
        ),
        (
            "tun_mixed",
            include_str!("golden/gui1251/tun_mixed.json"),
            true,
        ),
        (
            "http_only_auth",
            include_str!("golden/gui1251/http_only_auth.json"),
            false,
        ),
        (
            "socks_only_auth",
            include_str!("golden/gui1251/socks_only_auth.json"),
            false,
        ),
        (
            "mixed_auth",
            include_str!("golden/gui1251/mixed_auth.json"),
            false,
        ),
        (
            "composite_route_dns_profile",
            include_str!("golden/gui1251/composite_route_dns_profile.json"),
            false,
        ),
    ];

    for (name, source, expect_tun) in fixtures {
        let raw = parse_fixture(source);
        assert!(
            raw.get("schema_version").is_none(),
            "{name} should model GUI $schema-only output"
        );
        assert!(
            raw.get("$schema").is_some(),
            "{name} should carry GUI-generated $schema header"
        );

        let (cfg, ir) = load_production(raw.clone());
        assert_eq!(
            cfg.raw().get("schema_version").and_then(|v| v.as_u64()),
            Some(2),
            "{name} should be migrated to schema_version 2 internally"
        );
        assert!(
            !ir.outbounds.is_empty(),
            "{name} should lower outbounds through production IR"
        );
        assert!(
            ir.experimental
                .as_ref()
                .and_then(|experimental| experimental.cache_file.as_ref())
                .is_some(),
            "{name} should preserve experimental.cache_file"
        );
        let raw_cache_file = raw
            .get("experimental")
            .and_then(|experimental| experimental.get("cache_file"))
            .expect("fixture should carry experimental.cache_file");
        assert!(
            raw_cache_file.get("store_rdrc").is_none(),
            "{name} should model GUI 1.25.1 suppressed cache_file.store_rdrc"
        );
        assert_eq!(
            ir.experimental
                .as_ref()
                .and_then(|experimental| experimental.cache_file.as_ref())
                .map(|cache_file| cache_file.store_rdrc),
            Some(false),
            "{name} should keep suppressed store_rdrc false in IR"
        );

        let has_tun = ir
            .inbounds
            .iter()
            .any(|inbound| inbound.ty == InboundType::Tun);
        assert_eq!(has_tun, expect_tun, "{name} TUN expectation mismatch");
    }
}

#[test]
fn gui1251_composite_route_dns_profile_covers_low_priority_shape() {
    let raw = parse_fixture(include_str!(
        "golden/gui1251/composite_route_dns_profile.json"
    ));
    let (_, ir) = load_production(raw.clone());

    assert!(
        raw.pointer("/experimental/cache_file/store_rdrc").is_none(),
        "GUI 1.25.1 generator suppresses cache_file.store_rdrc"
    );
    assert_eq!(
        raw.pointer("/experimental/clash_api/external_controller")
            .and_then(Value::as_str),
        Some("[::1]:20123"),
        "fixture should pin bracketed IPv6 controller shape"
    );

    let mixed = raw
        .get("inbounds")
        .and_then(Value::as_array)
        .and_then(|items| items.iter().find(|item| item["type"] == "mixed"))
        .expect("fixture has mixed inbound");
    assert_eq!(mixed["listen"], "0.0.0.0");
    assert_eq!(mixed["users"][0]["username"], "gui");
    assert_eq!(mixed["users"][0]["password"], "pa:ss");

    assert!(
        ir.route
            .rules
            .iter()
            .any(|rule| rule.action == RuleAction::HijackDns),
        "route rules should cover GUI hijack-dns mode"
    );
    assert!(
        ir.route
            .rules
            .iter()
            .any(|rule| rule.action == RuleAction::Sniff),
        "route rules should cover GUI sniff mode"
    );
    assert!(
        raw.pointer("/route/rules")
            .and_then(Value::as_array)
            .is_some_and(|rules| rules
                .iter()
                .any(|rule| rule.get("clash_mode").and_then(Value::as_str) == Some("direct"))),
        "route rules should cover GUI clash_mode emission"
    );
    assert_eq!(ir.route.rule_set.len(), 1, "route rule_set should lower");

    let dns = ir.dns.as_ref().expect("fixture should lower DNS");
    assert!(
        dns.servers
            .iter()
            .any(|server| server.server_type.as_deref() == Some("fakeip")),
        "DNS servers should include GUI fakeip shape"
    );
    assert!(
        dns.rules
            .iter()
            .any(|rule| rule.clash_mode.as_deref() == Some("Global")),
        "DNS rules should cover GUI clash mode shape"
    );
    assert_eq!(dns.independent_cache, Some(true));
}

#[test]
fn gui1251_outbound_icon_hidden_are_accepted_and_ignored() {
    let raw = parse_fixture(include_str!(
        "golden/gui1251/default_mixed_tun_disabled.json"
    ));
    let (_, with_metadata) = load_production(raw.clone());

    let mut without_metadata = raw;
    for outbound in without_metadata
        .get_mut("outbounds")
        .and_then(|value| value.as_array_mut())
        .expect("fixture has outbounds")
    {
        let object = outbound.as_object_mut().expect("outbound is object");
        object.remove("icon");
        object.remove("hidden");
    }
    let (_, without_metadata) = load_production(without_metadata);

    assert_eq!(
        with_metadata, without_metadata,
        "GUI icon/hidden metadata must not enter runtime IR"
    );

    let direct: sb_config::outbound::Outbound = serde_json::from_value(json!({
        "type": "direct",
        "tag": "direct",
        "icon": "",
        "hidden": false
    }))
    .expect("raw outbound boundary should accept GUI metadata");
    let serialized = serde_json::to_value(&direct).expect("outbound should serialize");
    assert!(
        serialized.get("icon").is_none() && serialized.get("hidden").is_none(),
        "GUI metadata must be ignored by typed outbound config: {serialized}"
    );
}

#[test]
fn gui1251_wrong_schema_version_still_errors_in_direct_validator() {
    let issues = sb_config::validator::v2::validate_v2(
        &json!({
            "schema_version": 1,
            "outbounds": [{ "type": "direct", "tag": "direct" }]
        }),
        false,
    );

    assert!(
        issues.iter().any(|issue| {
            issue["kind"] == "error"
                && issue["ptr"] == "/schema_version"
                && issue["msg"] == "schema_version must be 2"
        }),
        "explicit wrong schema_version should remain a direct validation error: {issues:?}"
    );
}

#[test]
fn gui1251_strict_unknown_fields_remain_strict_outside_outbound_metadata() {
    assert_load_error_contains(
        json!({
            "unknown_root": true,
            "outbounds": [{ "type": "direct", "tag": "direct" }]
        }),
        "/unknown_root",
    );
    assert_load_error_contains(
        json!({
            "inbounds": [{
                "type": "mixed",
                "tag": "mixed-in",
                "listen": "127.0.0.1",
                "listen_port": 20122,
                "icon": "not-valid-here"
            }],
            "outbounds": [{ "type": "direct", "tag": "direct" }]
        }),
        "/inbounds/0/icon",
    );
    assert_load_error_contains(
        json!({
            "outbounds": [{ "type": "direct", "tag": "direct", "bogus": true }]
        }),
        "/outbounds/0/bogus",
    );
    assert_load_error_contains(
        json!({
            "outbounds": [{ "type": "direct", "tag": "direct" }],
            "route": { "final": "direct", "unknown_route_field": true }
        }),
        "/route/unknown_route_field",
    );
    assert_load_error_contains(
        json!({
            "outbounds": [{ "type": "direct", "tag": "direct" }],
            "dns": {
                "servers": [{ "tag": "dns", "type": "udp", "server": "8.8.8.8", "bogus": true }],
                "final": "dns"
            }
        }),
        "/dns/servers/0/bogus",
    );
    assert_load_error_contains(
        json!({
            "outbounds": [{ "type": "direct", "tag": "direct" }],
            "services": [{ "type": "resolved", "unknown_service_field": true }]
        }),
        "/services/0/unknown_service_field",
    );
    assert_load_error_contains(
        json!({
            "outbounds": [{ "type": "direct", "tag": "direct" }],
            "endpoints": [{ "type": "wireguard", "tag": "wg", "unknown_endpoint_field": true }]
        }),
        "/endpoints/0/unknown_endpoint_field",
    );
}

#[test]
fn gui1251_go_effective_tag_fallback_matches_duplicate_semantics() {
    assert_load_error_contains(
        json!({
            "inbounds": [
                { "type": "mixed", "listen": "127.0.0.1", "listen_port": 20122 },
                { "type": "http", "tag": "0", "listen": "127.0.0.1", "listen_port": 20121 }
            ],
            "outbounds": [{ "type": "direct", "tag": "direct" }]
        }),
        "duplicate inbound tag: 0",
    );

    assert_load_error_contains(
        json!({
            "outbounds": [{ "type": "direct" }],
            "endpoints": [{ "type": "wireguard", "tag": "0" }]
        }),
        "duplicate outbound/endpoint tag: 0",
    );

    let (_, ir) = load_production(json!({
        "inbounds": [
            { "type": "mixed", "tag": "shared", "listen": "127.0.0.1", "listen_port": 20122 }
        ],
        "outbounds": [{ "type": "direct", "tag": "shared" }]
    }));
    assert_eq!(ir.inbounds[0].tag.as_deref(), Some("shared"));
    assert_eq!(ir.outbounds[0].name.as_deref(), Some("shared"));
}
