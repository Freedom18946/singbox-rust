//! Configuration merge strategies for subscription updates.
//!
//! ## Merge Policy
//! When merging a subscription (`sub`) into a base configuration (`base`):
//!
//! - **Inbounds**: Preserved from `base` (locally controlled)
//! - **Outbounds**: Replaced by `sub` (deduplicated by name, `sub` takes precedence)
//! - **Rules**: Completely replaced by `sub` (subscriptions typically provide full rule sets)
//! - **Default outbound**: Use `sub.default_outbound` if present, otherwise keep `base`
//! - **Other fields**: Retained from `base`

use super::{Config, Outbound};
use serde_json::Value;

/// Non-destructive merge: returns a new [`Config`].
///
/// Merges a subscription configuration into a base configuration following
/// the module's merge policy.
///
/// # Examples
/// ```ignore
/// let base = Config::load("local.yaml")?;
/// let subscription = Config::load("subscription.json")?;
/// let merged = merge(base, subscription);
/// ```
#[must_use]
pub fn merge(base: Config, sub: Config) -> Config {
    let merged_raw = super::merge_raw(base.raw(), sub.raw());
    match Config::from_value(merged_raw) {
        Ok(cfg) => cfg,
        Err(_) => {
            let mut typed = merge_typed(base, sub);
            let value = serde_json::to_value(&typed).unwrap_or(Value::Null);
            let migrated = super::compat::migrate_to_v2(&value);
            match Config::from_value(migrated.clone()) {
                Ok(cfg) => cfg,
                Err(_) => {
                    typed.raw = migrated;
                    typed.ir = crate::validator::v2::to_ir_v1(&typed.raw);
                    typed
                }
            }
        }
    }
}

/// Typed merge fallback implementation.
///
/// Merges outbounds by name, with subscription taking precedence.
fn merge_typed(mut base: Config, sub: Config) -> Config {
    let mut out_map = std::collections::BTreeMap::<String, Outbound>::new();

    // First, insert base outbounds (as defaults)
    for o in base.outbounds.drain(..) {
        match &o {
            Outbound::Direct { name }
            | Outbound::Block { name }
            | Outbound::Socks5 { name, .. }
            | Outbound::Http { name, .. }
            | Outbound::Vless { name, .. }
            | Outbound::Vmess { name, .. }
            | Outbound::Trojan { name, .. }
            | Outbound::Tuic { name, .. } => {
                out_map.insert(name.clone(), o);
            }
        }
    }
    // Then override/append with subscription outbounds
    for o in sub.outbounds.into_iter() {
        match &o {
            Outbound::Direct { name }
            | Outbound::Block { name }
            | Outbound::Socks5 { name, .. }
            | Outbound::Http { name, .. }
            | Outbound::Vless { name, .. }
            | Outbound::Vmess { name, .. }
            | Outbound::Trojan { name, .. }
            | Outbound::Tuic { name, .. } => {
                out_map.insert(name.clone(), o);
            }
        }
    }

    let outbounds = out_map.into_values().collect::<Vec<_>>();

    Config {
        schema_version: base.schema_version.max(sub.schema_version), // Use higher version
        inbounds: base.inbounds,                                     // Locally controlled
        outbounds,
        rules: sub.rules, // Subscription overrides
        default_outbound: sub.default_outbound.or(base.default_outbound),
        raw: Value::Null,
        ir: crate::ir::ConfigIR::default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn merge_replace_rules_and_outbounds() -> anyhow::Result<()> {
        let base = Config::from_value(json!({
            "schema_version": 2,
            "inbounds": [{"type":"http","listen":"127.0.0.1:8080"}],
            "outbounds": [
                {"type":"direct","name":"direct"},
                {"type":"http","name":"old","server":"1.1.1.1","port":3128}
            ],
            "rules": [{
                "domain_suffix": ["old.com"],
                "outbound": "old"
            }]
        }))?;

        let sub = Config::from_value(json!({
            "schema_version": 2,
            "outbounds": [
                {
                    "type":"socks",
                    "name":"corp",
                    "server":"10.0.0.2",
                    "port":1080,
                    "credentials": {"username":"u","password":"p"}
                },
                {"type":"direct","name":"direct"}
            ],
            "route": {
                "rules": [{
                    "domain_suffix": ["new.com"],
                    "outbound": "corp"
                }],
                "default": "corp"
            }
        }))?;

        let m = merge(base, sub);
        assert!(m.inbounds.len() == 1);
        assert!(m
            .outbounds
            .iter()
            .any(|o| matches!(o, Outbound::Socks5{name, ..} if name=="corp")));
        assert!(m
            .outbounds
            .iter()
            .any(|o| matches!(o, Outbound::Direct{name, ..} if name=="direct")));
        assert!(m.rules.iter().any(|r| r.outbound == "corp"));
        assert_eq!(m.default_outbound.as_deref(), Some("corp"));
        Ok(())
    }
}
