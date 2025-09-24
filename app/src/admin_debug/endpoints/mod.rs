pub mod geoip;
pub mod normalize;
pub mod health;
pub mod metrics;
pub mod config;

#[cfg(any(
    feature = "subs_http",
    feature = "subs_clash",
    feature = "subs_singbox"
))]
pub mod subs;

#[cfg(feature = "sbcore_rules_tool")]
pub mod analyze;

#[cfg(feature = "route_sandbox")]
pub mod route_dryrun;

pub use geoip::handle as handle_geoip;
pub use normalize::handle as handle_normalize;
pub use health::handle as handle_health;
pub use metrics::handle as handle_metrics;
pub use config::{handle_get as handle_config_get, handle_put as handle_config_put};

#[cfg(any(
    feature = "subs_http",
    feature = "subs_clash",
    feature = "subs_singbox"
))]
pub use subs::handle as handle_subs;

#[cfg(feature = "sbcore_rules_tool")]
pub use analyze::handle as handle_analyze;

#[cfg(feature = "route_sandbox")]
pub use route_dryrun::handle as handle_route_dryrun;
