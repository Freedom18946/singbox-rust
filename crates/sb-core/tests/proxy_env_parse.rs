#![cfg(feature = "router")]
#![allow(clippy::await_holding_lock)]

use sb_core::router::runtime::*;
use std::sync::{Mutex, OnceLock};

fn serial_guard() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(())).lock().unwrap()
}

struct EnvVarGuard {
    key: &'static str,
    prev: Option<std::ffi::OsString>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: &str) -> Self {
        let prev = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, prev }
    }

    fn remove(key: &'static str) -> Self {
        let prev = std::env::var_os(key);
        std::env::remove_var(key);
        Self { key, prev }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        match self.prev.as_ref() {
            Some(v) => std::env::set_var(self.key, v),
            None => std::env::remove_var(self.key),
        }
    }
}

#[test]
fn parse_default_proxy_env_direct() {
    let _serial = serial_guard();
    let _a = EnvVarGuard::remove("SB_ROUTER_DEFAULT_PROXY");
    let _b = EnvVarGuard::remove("SB_ROUTER_DEFAULT_PROXY_KIND");
    let _c = EnvVarGuard::remove("SB_ROUTER_DEFAULT_PROXY_ADDR");
    let choice = parse_proxy_from_env();
    assert!(matches!(choice, ProxyChoice::Direct));
}

#[test]
fn parse_default_proxy_env_http() {
    let _serial = serial_guard();
    let _a = EnvVarGuard::set("SB_ROUTER_DEFAULT_PROXY", "http://127.0.0.1:3128");
    let _b = EnvVarGuard::remove("SB_ROUTER_DEFAULT_PROXY_KIND");
    let _c = EnvVarGuard::remove("SB_ROUTER_DEFAULT_PROXY_ADDR");
    let choice = parse_proxy_from_env();
    match choice {
        ProxyChoice::Http(s) => assert!(s.contains("3128")),
        _ => panic!("Expected HTTP proxy choice"),
    }
}

#[test]
fn parse_default_proxy_env_socks5() {
    let _serial = serial_guard();
    let _a = EnvVarGuard::set("SB_ROUTER_DEFAULT_PROXY", "socks5://127.0.0.1:1080");
    let _b = EnvVarGuard::remove("SB_ROUTER_DEFAULT_PROXY_KIND");
    let _c = EnvVarGuard::remove("SB_ROUTER_DEFAULT_PROXY_ADDR");
    let choice = parse_proxy_from_env();
    match choice {
        ProxyChoice::Socks5(s) => assert!(s.contains("1080")),
        _ => panic!("Expected SOCKS5 proxy choice"),
    }
}

#[test]
fn parse_default_proxy_env_kind_addr() {
    let _serial = serial_guard();
    let _a = EnvVarGuard::remove("SB_ROUTER_DEFAULT_PROXY");
    let _b = EnvVarGuard::set("SB_ROUTER_DEFAULT_PROXY_KIND", "http");
    let _c = EnvVarGuard::set("SB_ROUTER_DEFAULT_PROXY_ADDR", "127.0.0.1:8080");
    let choice = parse_proxy_from_env();
    match choice {
        ProxyChoice::Http(s) => assert!(s.contains("8080")),
        _ => panic!("Expected HTTP proxy choice from kind/addr"),
    }
}
