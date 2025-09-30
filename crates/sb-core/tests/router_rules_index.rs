#![cfg(feature = "router")]
use sb_core::router::{
    router_build_index_from_str, router_index_decide_exact_suffix, router_index_decide_ip,
};
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn rules_index_priority_and_limits() {
    let rules = r#"
    exact:api.example.com=proxy
    suffix:example.com=direct
    cidr4:10.0.0.0/8=direct
    cidr4:10.0.0.0/16=proxy
    cidr6:fd00::/8=direct
    default=direct
    "#;
    let idx = router_build_index_from_str(rules, 8192).expect("build");
    assert_eq!(
        router_index_decide_exact_suffix(&idx, "api.example.com").unwrap(),
        "proxy"
    );
    assert_eq!(
        router_index_decide_exact_suffix(&idx, "www.example.com").unwrap(),
        "direct"
    );
    // CIDR 前缀长优先
    let ip_a = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    assert_eq!(router_index_decide_ip(&idx, ip_a).unwrap(), "proxy"); // /16 覆盖 /8
    let ip_b = IpAddr::V6("fd00::1".parse().unwrap());
    assert_eq!(router_index_decide_ip(&idx, ip_b).unwrap(), "direct");
}

#[test]
fn rules_index_overflow_counting() {
    let mut s = String::new();
    for i in 0..100 {
        s.push_str(&format!("exact:h{}.x=direct\n", i));
    }
    // 上限设为 50，应报 Overflow
    let r = router_build_index_from_str(&s, 50);
    assert!(r.is_err());
}

#[test]
fn rules_index_ipv6_cidr_match() {
    // 验收：cidr6 规则必须正确解析（不能被 ':' 误切分）
    let rules = r#"
    cidr6:2001:db8::/32=proxy
    default=direct
    "#;
    let idx = router_build_index_from_str(rules, 8192).expect("build");
    use std::net::Ipv6Addr;
    let ip = IpAddr::V6("2001:db8::1".parse::<Ipv6Addr>().unwrap());
    assert_eq!(router_index_decide_ip(&idx, ip).unwrap(), "proxy");
}

#[test]
fn rules_index_comma_separated_on_same_line_ok() {
    // 验收：同行以逗号分隔多条规则应被正确拆分，不能把右值拼成 reject,suffix:.test
    let rules = r#"default=reject,suffix:.test=proxy"#;
    let idx = router_build_index_from_str(rules, 8192).expect("build");
    assert_eq!(
        router_index_decide_exact_suffix(&idx, "a.test").unwrap(),
        "proxy"
    );
    assert_eq!(
        router_index_decide_exact_suffix(&idx, "nope.example").unwrap_or(idx.default),
        "reject"
    );
}

#[test]
fn rules_index_unknown_kind_is_linted_but_ignored() {
    // 未知 kind 不应导致构建失败，但会在 stderr 打印并计数（metrics 下）
    let rules = r#"
    foo:bar=proxy
    suffix:example.com=direct
    default=proxy
    "#;
    let idx = router_build_index_from_str(rules, 8192).expect("build");
    assert_eq!(
        router_index_decide_exact_suffix(&idx, "x.example.com").unwrap(),
        "direct"
    );
}

#[test]
fn rules_index_dup_suffix_first_wins() {
    // 重复 suffix：first-wins（第二条应被跳过）
    let rules = r#"
    suffix:.test=direct
    suffix:.test=proxy
    default=reject
    "#;
    let idx = router_build_index_from_str(rules, 8192).expect("build");
    assert_eq!(
        router_index_decide_exact_suffix(&idx, "x.test").unwrap(),
        "direct"
    );
}

#[test]
fn rules_index_dup_default_last_wins() {
    // 重复 default：last-wins（第二条覆盖第一条）
    let rules = r#"
    default=direct
    default=proxy
    suffix:.test=reject
    "#;
    let idx = router_build_index_from_str(rules, 8192).expect("build");
    assert_eq!(idx.default, "proxy"); // last-wins
}

#[test]
fn suffix_map_exact_tail_hit_and_weird_suffix_fallback() {
    // suffix_map 精确尾段直查命中
    let rules = r#"
    suffix:.example.com=proxy
    # 不规则后缀（非标签边界），旧 ends_with 兜底仍然应生效
    suffix:mple.com=reject
    default=direct
    "#;
    let idx = router_build_index_from_str(rules, 8192).expect("build");
    // 精确尾段：应走 suffix_map 命中 "example.com" -> proxy
    assert_eq!(
        router_index_decide_exact_suffix(&idx, "a.b.example.com").unwrap(),
        "proxy"
    );
    // 不规则：suffix "mple.com" 不在 label 边界，直查不会匹配，但线扫兜底会命中 -> reject
    assert_eq!(
        router_index_decide_exact_suffix(&idx, "x.mple.com").unwrap(),
        "reject"
    );
    // 无匹配：走默认
    assert_eq!(
        router_index_decide_exact_suffix(&idx, "no.match").unwrap_or(idx.default),
        "direct"
    );
}

#[test]
fn rules_index_case_insensitive_host_and_suffix() {
    // suffix 大小写不敏感（通过 host 规范化实现）
    let rules = r#"
    suffix:.example.com=proxy
    exact:api.EXAMPLE.com=direct
    default=reject
    "#;
    let idx = router_build_index_from_str(rules, 8192).expect("build");
    // exact 大小写：规范化后应命中 direct
    assert_eq!(
        router_index_decide_exact_suffix(&idx, &sb_core::router::normalize_host("API.example.COM"))
            .unwrap(),
        "direct"
    );
    // suffix：规范化后 ends_with 命中 proxy
    assert_eq!(
        router_index_decide_exact_suffix(&idx, &sb_core::router::normalize_host("a.Example.Com"))
            .unwrap(),
        "proxy"
    );
}

#[cfg(feature = "idna")]
#[test]
fn rules_index_idna_punycode_normalization() {
    // 使用 Unicode 域名，规则给 punycode；host 通过 normalize_host 转成 punycode 后应命中
    let rules = r#"
    suffix:.xn--bcher-kva.example=proxy
    default=direct
    "#;
    let idx = router_build_index_from_str(rules, 8192).expect("build");
    let unicode_host = "www.BÜCHER.example"; // 注意大小写与 Umlaut
    let host_norm = sb_core::router::normalize_host(unicode_host);
    assert_eq!(
        router_index_decide_exact_suffix(&idx, &host_norm).unwrap(),
        "proxy"
    );
}
