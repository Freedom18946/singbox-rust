use crate::ir::{ConfigIR, Credentials};

fn resolve_cred(c: &mut Credentials) {
    if let Some(key) = &c.username_env {
        if let Ok(v) = std::env::var(key) {
            c.username = Some(v);
        }
    }
    if let Some(key) = &c.password_env {
        if let Ok(v) = std::env::var(key) {
            c.password = Some(v);
        }
    }
}

/// Parse and normalize credentials (ENV > Plaintext), avoiding downstream duplicate checks.
/// 解析并归一化认证字段（ENV > 明文），避免下游重复判断。
pub(super) fn normalize_credentials(ir: &mut ConfigIR) {
    for ob in &mut ir.outbounds {
        if let Some(c) = &mut ob.credentials {
            resolve_cred(c);
        }
    }
    for ib in &mut ir.inbounds {
        if let Some(c) = &mut ib.basic_auth {
            resolve_cred(c);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Credentials, OutboundIR, InboundIR, InboundType};

    // ───── outbound username_env / password_env resolve ─────

    #[test]
    fn outbound_username_env_resolved() {
        let key = "SB_TEST_CRED_USER_OB_01";
        std::env::set_var(key, "alice");
        let mut ir = ConfigIR::default();
        ir.outbounds.push(OutboundIR {
            credentials: Some(Credentials {
                username: None,
                password: None,
                username_env: Some(key.to_string()),
                password_env: None,
            }),
            ..Default::default()
        });
        normalize_credentials(&mut ir);
        assert_eq!(ir.outbounds[0].credentials.as_ref().unwrap().username.as_deref(), Some("alice"));
        std::env::remove_var(key);
    }

    #[test]
    fn outbound_password_env_resolved() {
        let key = "SB_TEST_CRED_PASS_OB_01";
        std::env::set_var(key, "secret123");
        let mut ir = ConfigIR::default();
        ir.outbounds.push(OutboundIR {
            credentials: Some(Credentials {
                username: None,
                password: None,
                username_env: None,
                password_env: Some(key.to_string()),
            }),
            ..Default::default()
        });
        normalize_credentials(&mut ir);
        assert_eq!(ir.outbounds[0].credentials.as_ref().unwrap().password.as_deref(), Some("secret123"));
        std::env::remove_var(key);
    }

    // ───── inbound basic_auth username_env / password_env resolve ─────

    #[test]
    fn inbound_basic_auth_username_env_resolved() {
        let key = "SB_TEST_CRED_USER_IB_01";
        std::env::set_var(key, "bob");
        let mut ir = ConfigIR::default();
        ir.inbounds.push(InboundIR {
            ty: InboundType::Mixed,
            basic_auth: Some(Credentials {
                username: None,
                password: None,
                username_env: Some(key.to_string()),
                password_env: None,
            }),
            ..Default::default()
        });
        normalize_credentials(&mut ir);
        assert_eq!(ir.inbounds[0].basic_auth.as_ref().unwrap().username.as_deref(), Some("bob"));
        std::env::remove_var(key);
    }

    #[test]
    fn inbound_basic_auth_password_env_resolved() {
        let key = "SB_TEST_CRED_PASS_IB_01";
        std::env::set_var(key, "pass456");
        let mut ir = ConfigIR::default();
        ir.inbounds.push(InboundIR {
            ty: InboundType::Mixed,
            basic_auth: Some(Credentials {
                username: None,
                password: None,
                username_env: None,
                password_env: Some(key.to_string()),
            }),
            ..Default::default()
        });
        normalize_credentials(&mut ir);
        assert_eq!(ir.inbounds[0].basic_auth.as_ref().unwrap().password.as_deref(), Some("pass456"));
        std::env::remove_var(key);
    }

    // ───── env missing does not overwrite existing plaintext ─────

    #[test]
    fn env_missing_does_not_overwrite_plaintext_username() {
        let key = "SB_TEST_CRED_NOEXIST_U_01";
        std::env::remove_var(key);
        let mut ir = ConfigIR::default();
        ir.outbounds.push(OutboundIR {
            credentials: Some(Credentials {
                username: Some("original".to_string()),
                password: None,
                username_env: Some(key.to_string()),
                password_env: None,
            }),
            ..Default::default()
        });
        normalize_credentials(&mut ir);
        assert_eq!(
            ir.outbounds[0].credentials.as_ref().unwrap().username.as_deref(),
            Some("original"),
            "missing env should not overwrite existing plaintext username"
        );
    }

    #[test]
    fn env_missing_does_not_overwrite_plaintext_password() {
        let key = "SB_TEST_CRED_NOEXIST_P_01";
        std::env::remove_var(key);
        let mut ir = ConfigIR::default();
        ir.outbounds.push(OutboundIR {
            credentials: Some(Credentials {
                username: None,
                password: Some("original_pass".to_string()),
                username_env: None,
                password_env: Some(key.to_string()),
            }),
            ..Default::default()
        });
        normalize_credentials(&mut ir);
        assert_eq!(
            ir.outbounds[0].credentials.as_ref().unwrap().password.as_deref(),
            Some("original_pass"),
            "missing env should not overwrite existing plaintext password"
        );
    }

    // ───── env present overwrites existing plaintext (ENV > Plaintext) ─────

    #[test]
    fn env_present_overwrites_plaintext() {
        let key_u = "SB_TEST_CRED_OVER_U_01";
        let key_p = "SB_TEST_CRED_OVER_P_01";
        std::env::set_var(key_u, "env_user");
        std::env::set_var(key_p, "env_pass");
        let mut ir = ConfigIR::default();
        ir.outbounds.push(OutboundIR {
            credentials: Some(Credentials {
                username: Some("old_user".to_string()),
                password: Some("old_pass".to_string()),
                username_env: Some(key_u.to_string()),
                password_env: Some(key_p.to_string()),
            }),
            ..Default::default()
        });
        normalize_credentials(&mut ir);
        let cred = ir.outbounds[0].credentials.as_ref().unwrap();
        assert_eq!(cred.username.as_deref(), Some("env_user"), "ENV should override plaintext username");
        assert_eq!(cred.password.as_deref(), Some("env_pass"), "ENV should override plaintext password");
        std::env::remove_var(key_u);
        std::env::remove_var(key_p);
    }

    // ───── no credentials / no basic_auth is a no-op ─────

    #[test]
    fn no_credentials_is_noop() {
        let mut ir = ConfigIR::default();
        ir.outbounds.push(OutboundIR::default());
        ir.inbounds.push(InboundIR {
            ty: InboundType::Mixed,
            ..Default::default()
        });
        normalize_credentials(&mut ir);
        assert!(ir.outbounds[0].credentials.is_none());
        assert!(ir.inbounds[0].basic_auth.is_none());
    }

    // ───── pins ─────

    #[test]
    fn wp30ad_pin_credential_normalization_owner_is_credentials_rs() {
        // WP-30ad pin: credential normalization owner has been migrated to
        // validator/v2/credentials.rs. The `normalize_credentials` function
        // lives in this module, not in mod.rs.
        let source = include_str!("credentials.rs");
        assert!(
            source.contains("pub(super) fn normalize_credentials"),
            "credential normalization owner must be in credentials.rs"
        );
        let mod_source = include_str!("mod.rs");
        assert!(
            !mod_source.contains("fn normalize_credentials"),
            "mod.rs must not contain normalize_credentials definition"
        );
        assert!(
            !mod_source.contains("fn resolve_cred"),
            "mod.rs must not contain resolve_cred definition"
        );
    }

    #[test]
    fn wp30ad_pin_to_ir_v1_delegates_credential_normalization() {
        // WP-30ad pin: the public to_ir_v1() entry still delegates credential
        // normalization instead of inlining it. After WP-30af, mod.rs delegates
        // to facade.rs, and facade.rs delegates to credentials::normalize_credentials.
        let mod_source = include_str!("mod.rs");
        assert!(
            mod_source.contains("facade::to_ir_v1(doc)"),
            "mod.rs to_ir_v1() must remain a thin facade delegate"
        );
        let facade_source = include_str!("facade.rs");
        assert!(
            facade_source.contains("credentials::normalize_credentials(&mut ir);"),
            "facade.rs to_ir_v1() must delegate to credentials::normalize_credentials"
        );
    }
}
