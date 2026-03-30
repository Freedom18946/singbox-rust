//! Public compat shell for normalization.
//!
//! The actual implementation lives in [`crate::ir::normalize`].
//! This module exists solely to preserve the `pub mod normalize` surface
//! declared in `lib.rs`.  All calls delegate directly.
//!
//! ## WP-30r
//!
//! Owner migrated to `ir/normalize.rs`.  This file is a thin delegate and
//! must not contain any logic beyond forwarding.

use crate::ir::{ConfigIR, RuleIR};

/// Normalize a single rule's tokens (domain, port, network, protocol).
///
/// Delegates to [`crate::ir::normalize::normalize_rule`].
pub fn normalize_rule(r: &mut RuleIR) {
    crate::ir::normalize::normalize_rule(r);
}

/// Normalize all route rules in a config IR.
///
/// Delegates to [`crate::ir::normalize::normalize_config`].
pub fn normalize_config(cfg: &mut ConfigIR) {
    crate::ir::normalize::normalize_config(cfg);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::RuleIR;

    #[test]
    fn wp30r_pin_compat_shell_is_pure_delegate() {
        // WP-30r pin: this module is a thin compat shell.  It must not contain
        // any logic — only forwarding to crate::ir::normalize.
        // If this test compiles and passes, the delegate wiring is intact.
        let mut r = RuleIR {
            domain: vec!["DELEGATE.COM".into()],
            ..Default::default()
        };
        normalize_rule(&mut r);
        assert_eq!(r.domain, vec!["delegate.com"]);
    }

    #[test]
    fn wp30r_pin_compat_shell_normalize_config_delegates() {
        // WP-30r pin: normalize_config through compat shell produces identical
        // results to direct ir::normalize call.
        let mut cfg = crate::ir::ConfigIR::default();
        cfg.route.rules.push(RuleIR {
            domain: vec!["UPPER.COM".into()],
            port: vec!["80-82".into(), "81".into()],
            ..Default::default()
        });
        normalize_config(&mut cfg);
        assert_eq!(cfg.route.rules[0].domain, vec!["upper.com"]);
        assert_eq!(cfg.route.rules[0].port, vec!["80-82"]);
    }
}
