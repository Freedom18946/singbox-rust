#![allow(clippy::await_holding_lock)]

use sb_core::router::runtime::*;
use sb_core::runtime_options::RouterRuntimeOptions;

#[test]
fn parse_default_proxy_env_direct() {
    let choice = parse_proxy(&RouterRuntimeOptions::default());
    assert!(matches!(choice, ProxyChoice::Direct));
}

#[test]
fn parse_default_proxy_env_http() {
    let options = RouterRuntimeOptions {
        default_proxy: Some("http://127.0.0.1:3128".into()),
        ..Default::default()
    };
    let choice = parse_proxy(&options);
    match choice {
        ProxyChoice::Http(s) => assert!(s.contains("3128")),
        _ => panic!("Expected HTTP proxy choice"),
    }
}

#[test]
fn parse_default_proxy_env_socks5() {
    let options = RouterRuntimeOptions {
        default_proxy: Some("socks5://127.0.0.1:1080".into()),
        ..Default::default()
    };
    let choice = parse_proxy(&options);
    match choice {
        ProxyChoice::Socks5(s) => assert!(s.contains("1080")),
        _ => panic!("Expected SOCKS5 proxy choice"),
    }
}

#[test]
fn parse_default_proxy_env_kind_addr() {
    let options = RouterRuntimeOptions {
        default_proxy_kind: Some("http".into()),
        default_proxy_addr: Some("127.0.0.1:8080".into()),
        ..Default::default()
    };
    let choice = parse_proxy(&options);
    match choice {
        ProxyChoice::Http(s) => assert!(s.contains("8080")),
        _ => panic!("Expected HTTP proxy choice from kind/addr"),
    }
}
