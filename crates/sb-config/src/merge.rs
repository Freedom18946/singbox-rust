//! 订阅合并策略：把订阅（sub）合并进本地（base）
//! 约定：
//! - 保留 base.inbounds（入站由本地控制）
//! - 用 sub.outbounds 覆盖（同名去重，以 sub 为准）
//! - 用 sub.rules 完全替换（机场订阅通常自带完整规则集）
//! - 若 sub.default_outbound 存在，则覆盖 base
//! - 其余字段沿用 base
use super::{Config, Outbound};

/// 非破坏性合并：返回新 Config
pub fn merge(base: Config, sub: Config) -> Config {
    let mut out_map = std::collections::BTreeMap::<String, Outbound>::new();
    // 先装入 base 的出站（作为缺省）
    for o in base.outbounds.into_iter() {
        match &o {
            Outbound::Direct { name }
            | Outbound::Block { name }
            | Outbound::Socks5 { name, .. }
            | Outbound::Http { name, .. }
            | Outbound::Vless { name, .. } => {
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
            | Outbound::Vless { name, .. } => {
                out_map.insert(name.clone(), o);
            }
        }
    }

    let outbounds = out_map.into_values().collect::<Vec<_>>();

    Config {
        inbounds: base.inbounds, // 本地掌控
        outbounds,
        rules: sub.rules, // 订阅覆盖
        default_outbound: sub.default_outbound.or(base.default_outbound),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Auth, Rule};

    #[test]
    fn merge_replace_rules_and_outbounds() {
        let base = Config {
            inbounds: vec![super::super::Inbound::Http {
                listen: "127.0.0.1:8080".into(),
            }],
            outbounds: vec![
                Outbound::Direct {
                    name: "direct".into(),
                },
                Outbound::Http {
                    name: "old".into(),
                    server: "1.1.1.1".into(),
                    port: 3128,
                    auth: None,
                },
            ],
            rules: vec![Rule {
                domain_suffix: vec!["old.com".into()],
                outbound: "old".into(),
                ..Default::default()
            }],
            default_outbound: None,
        };

        let sub = Config {
            inbounds: vec![], // 忽略
            outbounds: vec![
                Outbound::Socks5 {
                    name: "corp".into(),
                    server: "10.0.0.2".into(),
                    port: 1080,
                    auth: Some(Auth {
                        username: "u".into(),
                        password: "p".into(),
                    }),
                },
                Outbound::Direct {
                    name: "direct".into(),
                }, // 覆盖同名
            ],
            rules: vec![Rule {
                domain_suffix: vec!["new.com".into()],
                outbound: "corp".into(),
                ..Default::default()
            }],
            default_outbound: Some("corp".into()),
        };

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
