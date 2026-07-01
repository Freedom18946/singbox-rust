#![no_main]
//! Structured config parsing fuzzer
//!
//! Uses the arbitrary crate to generate structured JSON-like config data
//! for more targeted fuzzing of the sb-config parsing and validation pipeline.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FuzzConfig {
    schema_version: u8,
    has_inbounds: bool,
    inbound_type: u8,
    inbound_listen: String,
    inbound_port: u16,
    has_outbounds: bool,
    outbound_type: u8,
    outbound_name: String,
    outbound_server: String,
    outbound_port: u16,
    has_route: bool,
    route_domain_suffix: Vec<String>,
    route_outbound: String,
    default_outbound: Option<String>,
}

impl FuzzConfig {
    fn to_json(&self) -> serde_json::Value {
        let mut obj = serde_json::Map::new();
        obj.insert(
            "schema_version".to_string(),
            serde_json::Value::from(self.schema_version as u64),
        );

        if self.has_inbounds {
            let inbound_type_str = match self.inbound_type % 3 {
                0 => "http",
                1 => "socks",
                _ => "mixed",
            };
            let inbound = serde_json::json!({
                "type": inbound_type_str,
                "listen": self.inbound_listen,
                "listen_port": self.inbound_port,
            });
            obj.insert(
                "inbounds".to_string(),
                serde_json::Value::Array(vec![inbound]),
            );
        }

        if self.has_outbounds {
            let outbound_type_str = match self.outbound_type % 4 {
                0 => "direct",
                1 => "block",
                2 => "socks",
                _ => "http",
            };
            let outbound = serde_json::json!({
                "type": outbound_type_str,
                "tag": self.outbound_name,
                "server": self.outbound_server,
                "server_port": self.outbound_port,
            });
            obj.insert(
                "outbounds".to_string(),
                serde_json::Value::Array(vec![outbound]),
            );
        }

        if self.has_route {
            let suffixes: Vec<serde_json::Value> = self
                .route_domain_suffix
                .iter()
                .map(|s| serde_json::Value::String(s.clone()))
                .collect();
            let rule = serde_json::json!({
                "domain_suffix": suffixes,
                "outbound": self.route_outbound,
            });
            let mut route = serde_json::Map::new();
            route.insert("rules".to_string(), serde_json::Value::Array(vec![rule]));
            if let Some(def) = &self.default_outbound {
                route.insert(
                    "default".to_string(),
                    serde_json::Value::String(def.clone()),
                );
            }
            obj.insert("route".to_string(), serde_json::Value::Object(route));
        }

        serde_json::Value::Object(obj)
    }
}

fuzz_target!(|cfg: FuzzConfig| {
    let raw = cfg.to_json();

    // Exercise the full config parsing pipeline.
    let _ = sb_config::config_from_raw_value(raw.clone());

    // Exercise the lighter-weight path.
    let _ = sb_config::Config::from_value(raw.clone());

    // Exercise compatibility migration.
    let (migrated, _) = sb_config::compat::migrate_to_v2(&raw);
    let _ = sb_config::validator::v2::validate_v2(&migrated, false);
});
