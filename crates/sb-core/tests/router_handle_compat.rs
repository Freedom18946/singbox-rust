#![cfg(feature = "router")]

use sb_core::outbound::OutboundKind;
use sb_core::router::{Router, RouterHandle};

#[test]
fn compat_router_default_is_unresolved() {
    let handle = RouterHandle::new(Router::default());
    assert_eq!(handle.index_snapshot().default, "unresolved");
}

#[test]
fn compat_router_handle_honors_with_default_target() {
    let handle = RouterHandle::new(Router::with_default("socks5-out"));
    assert_eq!(handle.index_snapshot().default, "socks5-out");
}

#[test]
fn compat_router_handle_replace_updates_default_and_generation() {
    let handle = RouterHandle::new(Router::with_default("proxy"));
    assert_eq!(handle.index_snapshot().gen, 1);

    handle.replace(Router::with_default("reject"));

    let idx = handle.index_snapshot();
    assert_eq!(idx.default, "reject");
    assert_eq!(idx.gen, 2);
}

#[test]
fn compat_router_with_default_accepts_outbound_kind() {
    let handle = RouterHandle::new(Router::with_default(OutboundKind::Direct));
    assert_eq!(handle.index_snapshot().default, "direct");
}
