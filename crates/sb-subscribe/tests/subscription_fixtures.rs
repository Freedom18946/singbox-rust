//! H-10: subscription parser fixture regression set.
//!
//! Pins current parser behavior across the three common provider formats and,
//! crucially, documents how each handles unknown/unsupported entries — the audit's
//! H-10 concern: "is an unknown type silently treated as success?". Fixtures are
//! static files under `tests/fixtures/` and require no network.
//!
//! Behavior baselines encoded here (see package08 evidence for follow-up):
//! - Clash YAML & sing-box JSON: ANY proxy/outbound `type` is passed through
//!   verbatim (no whitelist) — unknown types are silently accepted, and there is
//!   no skip/unknown counter returned to the caller.
//! - URI-line provider: unknown schemes (e.g. `tuic://`) and malformed lines are
//!   silently DROPPED (not counted); the result length simply shrinks.
//! - The JSON-array provider path is the one path that rejects an unknown `ty`
//!   loudly (closed enum, no `#[serde(other)]`), surfacing as `Err`.

#[cfg(feature = "subs_clash")]
#[test]
fn clash_yaml_parses_known_types_and_passes_unknown_through() {
    let profile = sb_subscribe::parse_clash::parse(include_str!("fixtures/clash_basic.yaml"))
        .expect("clash fixture must parse");
    let kinds = profile.outbounds_kinds();
    // Mainstream types are preserved as-is.
    assert!(
        kinds.contains(&"clash-trojan:trojan".to_string()),
        "{kinds:?}"
    );
    assert!(
        kinds.contains(&"clash-vmess:vmess".to_string()),
        "{kinds:?}"
    );
    assert!(
        kinds.contains(&"clash-vless:vless".to_string()),
        "{kinds:?}"
    );
    assert!(kinds.contains(&"clash-ss:ss".to_string()), "{kinds:?}");
    // BASELINE: an unknown type ("brook") is silently passed through, NOT skipped.
    // Records current behavior — there is no unknown counter for the caller.
    assert!(
        kinds.contains(&"clash-unknown:brook".to_string()),
        "unknown clash type is currently passed through verbatim: {kinds:?}"
    );
    assert_eq!(profile.outbounds.len(), 5);
    assert!(
        profile.rules_len() >= 1,
        "clash rules should map to DSL lines"
    );
}

#[cfg(feature = "subs_singbox")]
#[test]
fn singbox_json_preserves_outbound_kinds_and_route_rules() {
    let profile = sb_subscribe::parse_singbox::parse(include_str!("fixtures/singbox_basic.json"))
        .expect("sing-box fixture must parse");
    let kinds = profile.outbounds_kinds();
    assert!(kinds.contains(&"sb-trojan:trojan".to_string()), "{kinds:?}");
    assert!(kinds.contains(&"sb-vmess:vmess".to_string()), "{kinds:?}");
    assert!(
        kinds.contains(&"sb-ss:shadowsocks".to_string()),
        "{kinds:?}"
    );
    assert!(kinds.contains(&"select:selector".to_string()), "{kinds:?}");
    assert_eq!(profile.outbounds.len(), 5);
    assert!(
        profile.rules_len() >= 1,
        "route.rules should expand to DSL lines"
    );
}

#[cfg(feature = "subs_provider_parse")]
#[test]
fn provider_uri_list_parses_known_and_drops_unknown() {
    let nodes = sb_subscribe::provider_parse::parse_proxy_content(include_str!(
        "fixtures/provider_uris.txt"
    ))
    .expect("provider uri fixture must parse");
    // 7 input lines: 5 supported schemes parse; `tuic://` (unsupported) and one
    // malformed line are silently dropped, so the length shrinks to 5.
    let summary: Vec<String> = nodes
        .iter()
        .map(|n| format!("{:?}/{:?}", n.ty, n.name))
        .collect();
    assert_eq!(
        nodes.len(),
        5,
        "unknown scheme + malformed line must be dropped; got: {summary:?}"
    );
    // Each supported scheme is recognized (Debug of the OutboundType tag).
    let kinds: Vec<String> = nodes.iter().map(|n| format!("{:?}", n.ty)).collect();
    for expected in ["Trojan", "Vless", "Hysteria2", "Vmess", "Shadowsocks"] {
        assert!(
            kinds.contains(&expected.to_string()),
            "missing {expected} in {kinds:?}"
        );
    }
    // The unsupported tuic:// node must NOT silently reappear as another type.
    let names: Vec<String> = nodes.iter().filter_map(|n| n.name.clone()).collect();
    assert!(
        !names.iter().any(|n| n.contains("tuic")),
        "tuic node must be dropped, not silently relabeled: {names:?}"
    );
    // A known node carries its parsed fields end-to-end.
    let trojan = nodes
        .iter()
        .find(|n| format!("{:?}", n.ty) == "Trojan")
        .expect("trojan node present");
    assert_eq!(trojan.server.as_deref(), Some("trojan.example.com"));
    assert_eq!(trojan.port, Some(443));
}

#[cfg(feature = "subs_provider_parse")]
#[test]
fn provider_json_array_rejects_unknown_type_loudly() {
    // The JSON-array path is the ONE provider path that does NOT silently accept an
    // unknown type: OutboundType is a closed enum with no #[serde(other)], so an
    // unknown `ty` fails deserialization and surfaces as Err (not a silent skip).
    let r = sb_subscribe::provider_parse::parse_proxy_content(
        r#"[{"ty":"totally_unknown_xyz","server":"1.2.3.4","port":1}]"#,
    );
    assert!(
        r.is_err(),
        "unknown ty in JSON array must be rejected, not silently accepted"
    );
}
