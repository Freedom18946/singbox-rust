use sb_core::router::runtime::*;

#[test]
fn parse_default_proxy_env_direct() {
    std::env::remove_var("SB_ROUTER_DEFAULT_PROXY");
    std::env::remove_var("SB_ROUTER_DEFAULT_PROXY_KIND");
    std::env::remove_var("SB_ROUTER_DEFAULT_PROXY_ADDR");
    let choice = parse_proxy_from_env();
    assert!(matches!(choice, ProxyChoice::Direct));
}

#[test]
fn parse_default_proxy_env_http() {
    std::env::set_var("SB_ROUTER_DEFAULT_PROXY", "http://127.0.0.1:3128");
    std::env::remove_var("SB_ROUTER_DEFAULT_PROXY_KIND");
    std::env::remove_var("SB_ROUTER_DEFAULT_PROXY_ADDR");
    let choice = parse_proxy_from_env();
    match choice {
        ProxyChoice::Http(s) => assert!(s.contains("3128")),
        _ => assert!(false, "Expected HTTP proxy choice"),
    }
}

#[test]
fn parse_default_proxy_env_socks5() {
    std::env::set_var("SB_ROUTER_DEFAULT_PROXY", "socks5://127.0.0.1:1080");
    std::env::remove_var("SB_ROUTER_DEFAULT_PROXY_KIND");
    std::env::remove_var("SB_ROUTER_DEFAULT_PROXY_ADDR");
    let choice = parse_proxy_from_env();
    match choice {
        ProxyChoice::Socks5(s) => assert!(s.contains("1080")),
        _ => assert!(false, "Expected SOCKS5 proxy choice"),
    }
}

#[test]
fn parse_default_proxy_env_kind_addr() {
    std::env::remove_var("SB_ROUTER_DEFAULT_PROXY");
    std::env::set_var("SB_ROUTER_DEFAULT_PROXY_KIND", "http");
    std::env::set_var("SB_ROUTER_DEFAULT_PROXY_ADDR", "127.0.0.1:8080");
    let choice = parse_proxy_from_env();
    match choice {
        ProxyChoice::Http(s) => assert!(s.contains("8080")),
        _ => assert!(false, "Expected HTTP proxy choice from kind/addr"),
    }
}
