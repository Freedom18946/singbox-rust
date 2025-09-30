pub mod config;
pub mod geoip;
pub mod health;
pub mod metrics;
pub mod normalize;

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

pub use config::{handle_get as handle_config_get, handle_put as handle_config_put};
pub use geoip::handle as handle_geoip;
pub use health::handle as handle_health;
pub use normalize::handle as handle_normalize;

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
