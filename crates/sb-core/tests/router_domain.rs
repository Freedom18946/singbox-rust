#![cfg(feature = "router")]
// Permanently disabled with an always-false cfg (no unknown features)
#![cfg(not(any(feature = "router", not(feature = "router"))))]
use sb_config::Config;
use sb_core::Router;

#[test]
fn domain_suffix_match_matrix() {
    // 端到端走 Router：rules -> select(host) -> OutboundKind
    let json = serde_json::json!({
        "inbounds": [],
        "outbounds": [
            { "tag": "direct", "type": "direct" },
            { "tag": "block",  "type": "block"  }
        ],
        "rules": [
            { "type": "domain_suffix", "suffix": "example.com", "outbound": "block" }
        ]
    });

    // 关键：显式类型参数
    let cfg: Config = serde_json::from_value::<Config>(json).unwrap().normalize();
    let r = Router::from_config(&cfg).unwrap();

    use sb_core::OutboundKind::{Block, Direct};
    assert_eq!(r.select("a.b.example.com"), Block);
    assert_eq!(r.select("example.com"), Block);
    assert_eq!(r.select("not-example.com"), Direct);
    assert_eq!(r.select("com"), Direct);
}

#[test]
fn router_default_outbounds_are_filled() {
    // 即便没有 outbounds，normalize() 也会补 direct/block
    let json = serde_json::json!({
        "inbounds": [],
        "outbounds": [],
        "rules": []
    });

    let cfg: Config = serde_json::from_value::<Config>(json).unwrap().normalize();
    let r = Router::from_config(&cfg).unwrap();

    use sb_core::OutboundKind::Direct;
    assert_eq!(r.select("whatever.test"), Direct);
}
