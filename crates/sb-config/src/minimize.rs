//! Rule minimization (dedup/fold) with negation guard.
//! - 当存在任一 not_* 维度时，仅执行 normalize（由上层打印 MINIMIZE_SKIPPED）
use crate::ir::ConfigIR;
use crate::normalize::normalize_config;

fn fold_domains(v: &mut Vec<String>) {
    // 输入已规范化排序；去重即可
    v.dedup();
}

fn fold_cidrs(_v: &mut Vec<String>) {
    // TODO: 真实 CIDR 合并（区间树/前缀树）；此处先占位，保证接口稳定
    // 留空表示保持规范化顺序与去重，后续补充
}

pub enum MinimizeAction {
    SkippedByNegation,
    Applied,
}

pub fn minimize_config(cfg: &mut ConfigIR) -> MinimizeAction {
    if cfg.has_any_negation() {
        normalize_config(cfg);
        return MinimizeAction::SkippedByNegation;
    }
    normalize_config(cfg);
    for r in &mut cfg.route.rules {
        fold_domains(&mut r.domain);
        fold_domains(&mut r.not_domain);
        fold_cidrs(&mut r.ipcidr);
        fold_cidrs(&mut r.not_ipcidr);
    }
    MinimizeAction::Applied
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{ConfigIR, RuleIR};
    #[test]
    fn skip_when_neg() {
        let mut cfg = ConfigIR::default();
        cfg.route.rules.push(RuleIR {
            not_domain: vec!["x.com".into()],
            domain: vec!["a.com".into(), "a.com".into()],
            ..Default::default()
        });
        let act = minimize_config(&mut cfg);
        match act {
            MinimizeAction::SkippedByNegation => {}
            _ => panic!("should skip"),
        }
        assert_eq!(cfg.route.rules[0].domain, vec!["a.com"]); // 仍完成规范化
    }
}
