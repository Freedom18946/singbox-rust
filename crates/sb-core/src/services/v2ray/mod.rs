#[cfg(feature = "service_v2ray_api")]
pub mod stats {
    pub mod command {
        tonic::include_proto!("v2ray.core.app.stats.command");
    }
}
