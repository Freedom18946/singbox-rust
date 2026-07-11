//! Optional control-plane services hosted outside `sb-core`.

#[cfg(feature = "ssmapi")]
pub mod ssmapi;

#[cfg(feature = "v2ray-api")]
pub mod v2ray_api;

#[cfg(feature = "v2ray-api")]
pub(crate) mod v2ray_stats_proto {
    tonic::include_proto!("v2ray.core.app.stats.command");
}

/// Register sb-api-owned service builders in sb-core's implementation-neutral registries.
pub fn register_all() {
    #[cfg(feature = "ssmapi")]
    sb_core::service::register_service(
        sb_config::ir::ServiceType::Ssmapi,
        ssmapi::build_ssmapi_service,
    );

    #[cfg(feature = "v2ray-api")]
    sb_core::service::register_v2ray_server_factory(|config| {
        std::sync::Arc::new(v2ray_api::V2RayApiServer::new(config))
    });
}
