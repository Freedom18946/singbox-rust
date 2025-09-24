// crates/sb-core/src/config/mod.rs
#[cfg(feature = "schema-v2")]
pub mod schema_v2;

#[cfg(feature = "schema-v2")]
pub mod types_route;

#[cfg(feature = "fuzzing")]
pub fn try_parse_str(s: &str) -> Result<(), ()> {
    let _: Result<serde_yaml::Value, _> = serde_yaml::from_str(s);
    Ok(())
}
