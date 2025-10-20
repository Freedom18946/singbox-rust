//! 订阅合并策略：把订阅（sub）合并进本地（base）
//! 约定：
//! - 保留 base.inbounds（入站由本地控制）
//! - 用 sub.outbounds 覆盖（同名去重，以 sub 为准）
//! - 用 sub.rules 完全替换（机场订阅通常自带完整规则集）
//! - 若 sub.default_outbound 存在，则覆盖 base
//! - 其余字段沿用 base
use super::{Config, Outbound};
use serde_json::Value;

/// 非破坏性合并：返回新 Config
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

fn merge_typed(mut base: Config, sub: Config) -> Config {
    let mut out_map = std::collections::BTreeMap::<String, Outbound>::new();
    // 先装入 base 的出站（作为缺省）
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
    // 再用 sub 覆盖/追加
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
        schema_version: base.schema_version.max(sub.schema_version), // 取较高版本
        inbounds: base.inbounds,                                     // 本地掌控
        outbounds,
        rules: sub.rules, // 订阅覆盖
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
    fn merge_replace_rules_and_outbounds() {
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
        }))
        .unwrap();

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
        }))
        .unwrap();

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
    }
}
