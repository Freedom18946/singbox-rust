use sb_core::router::{
    normalize_host, router_build_index_from_str_with_options, router_index_decide_exact_suffix,
};
use sb_core::runtime_options::RouterRuntimeOptions;

#[test]
fn suffix_strict_only_uses_label_tail_map() {
    // 开启严格模式
    let rules = r#"
    suffix:.example.com=proxy
    # "非标签边界"的 weird 后缀
    suffix:mple.com=reject
    default=unresolved
    "#;
    let options = RouterRuntimeOptions {
        suffix_strict: true,
        ..RouterRuntimeOptions::default()
    };
    let idx = router_build_index_from_str_with_options(rules, 8192, &options).expect("build");
    let h1 = normalize_host("api.example.com");
    assert_eq!(
        router_index_decide_exact_suffix(&idx, &h1).unwrap(),
        "proxy"
    );
    // 严格模式下，weird 后缀不再线扫匹配，应走 default
    let h2 = normalize_host("yample.com");
    assert_eq!(
        router_index_decide_exact_suffix(&idx, &h2).unwrap_or(idx.default),
        "unresolved"
    );
}
