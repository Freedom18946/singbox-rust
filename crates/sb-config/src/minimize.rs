//! Public compat shell for minimization.
//!
//! The actual implementation lives in [`crate::ir::minimize`].
//! This module exists solely to preserve the `pub mod minimize` surface
//! declared in `lib.rs`.  All calls delegate directly.
//!
//! ## WP-30s
//!
//! Owner migrated to `ir/minimize.rs`.  This file is a thin delegate and
//! must not contain any logic beyond forwarding.

use crate::ir::ConfigIR;

/// Result of a minimization pass.
///
/// Re-exported from [`crate::ir::minimize::MinimizeAction`].
pub enum MinimizeAction {
    SkippedByNegation,
    Applied,
}

/// Minimize a config IR: normalize, then optionally fold/dedup.
///
/// Delegates to [`crate::ir::minimize::minimize_config`].
pub fn minimize_config(cfg: &mut ConfigIR) -> MinimizeAction {
    match crate::ir::minimize::minimize_config(cfg) {
        crate::ir::minimize::MinimizeAction::SkippedByNegation => {
            MinimizeAction::SkippedByNegation
        }
        crate::ir::minimize::MinimizeAction::Applied => MinimizeAction::Applied,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::RuleIR;

    #[test]
    fn wp30s_pin_compat_shell_is_pure_delegate() {
        // WP-30s pin: this module is a thin compat shell.  It must not contain
        // any logic — only forwarding to crate::ir::minimize.
        // If this test compiles and passes, the delegate wiring is intact.
        let mut cfg = ConfigIR::default();
        cfg.route.rules.push(RuleIR {
            domain: vec!["DELEGATE.COM".into(), "DELEGATE.COM".into()],
            ..Default::default()
        });
        let act = minimize_config(&mut cfg);
        assert!(matches!(act, MinimizeAction::Applied));
        assert_eq!(cfg.route.rules[0].domain, vec!["delegate.com"]);
    }

    #[test]
    fn wp30s_pin_compat_shell_minimize_config_delegates() {
        // WP-30s pin: minimize_config through compat shell produces identical
        // results to direct ir::minimize call.
        let mut cfg = ConfigIR::default();
        cfg.route.rules.push(RuleIR {
            not_domain: vec!["blocked.com".into()],
            domain: vec!["UPPER.COM".into()],
            ..Default::default()
        });
        let act = minimize_config(&mut cfg);
        assert!(matches!(act, MinimizeAction::SkippedByNegation));
        assert_eq!(cfg.route.rules[0].domain, vec!["upper.com"]);
    }
}
