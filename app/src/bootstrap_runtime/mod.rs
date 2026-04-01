#[cfg(any(feature = "clash_api", feature = "v2ray_api"))]
pub(crate) mod api_services;
pub(crate) mod dns_apply;
pub(crate) mod inbounds;
pub(crate) mod proxy_registry;
pub(crate) mod router_helpers;
pub(crate) mod runtime_shell;

#[cfg(any(feature = "clash_api", feature = "v2ray_api"))]
pub(crate) use api_services::ServiceHandle;
pub(crate) use runtime_shell::Runtime;
