// crates/sb-core/src/config/schema_v2.rs
#![cfg(feature = "schema-v2")]

//! Schema v2 compatibility layer and legacy support
//!
//! This module provides backward compatibility with the existing schema_v2 interface
//! while delegating to the new enhanced types in types_route.rs

// Re-export schemars and serde for compatibility if needed
#[allow(unused_imports)]
use schemars::{schema_for, JsonSchema};
#[allow(unused_imports)]
use serde::{Deserialize, Serialize};

// Re-export the enhanced types from types_route
pub use super::types_route::{
    schema_v2, ConfigV2, DnsV2, DomainPattern, InboundV2, OutboundV2, RouteRuleV2, RouteV2, WhenV2,
};

// Legacy type aliases for backward compatibility
pub type Config = ConfigV2;
pub type Route = RouteV2;
pub type RouteRule = RouteRuleV2;
pub type Inbound = InboundV2;
pub type Outbound = OutboundV2;

// Backward compatibility alias
pub fn dump_v2_schema() -> serde_json::Value {
    schema_v2()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_backward_compatibility_aliases() {
        use serde_json;

        // Test that legacy type aliases work
        let config = Config::default();
        assert!(serde_json::to_value(&config).is_ok());

        let route = Route::default();
        assert!(serde_json::to_value(&route).is_ok());
    }

    #[test]
    fn test_schema_generation_compatibility() {
        let schema1 = schema_v2();
        let schema2 = dump_v2_schema();
        assert_eq!(schema1, schema2);
    }
}
