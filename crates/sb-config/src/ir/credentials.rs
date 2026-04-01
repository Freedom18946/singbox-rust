use serde::{Deserialize, Serialize};

/// Authentication credentials with optional environment variable support.
/// 带有可选环境变量支持的认证凭据。
///
/// Deserialization goes through [`super::raw::RawCredentials`] which carries
/// `#[serde(deny_unknown_fields)]` (WP-30i).
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub struct Credentials {
    /// Username (literal value).
    #[serde(default)]
    pub username: Option<String>,
    /// Password (literal value).
    #[serde(default)]
    pub password: Option<String>,
    /// Read username from this environment variable (takes precedence over `username`).
    #[serde(default)]
    pub username_env: Option<String>,
    /// Read password from this environment variable (takes precedence over `password`).
    #[serde(default)]
    pub password_env: Option<String>,
}

impl<'de> Deserialize<'de> for Credentials {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        super::raw::RawCredentials::deserialize(deserializer).map(Into::into)
    }
}

#[cfg(test)]
mod tests {
    use super::Credentials;
    use serde_json::json;

    #[test]
    fn credentials_raw_bridge_rejects_unknown_fields() {
        let result = serde_json::from_value::<Credentials>(json!({
            "username": "alice",
            "extra": true
        }));
        assert!(
            result.is_err(),
            "Credentials should reject unknown field via RawCredentials bridge"
        );
    }

    #[test]
    fn credentials_roundtrip_preserves_env_shape() {
        let original = Credentials {
            username: Some("alice".to_string()),
            password: Some("secret".to_string()),
            username_env: Some("SB_USER".to_string()),
            password_env: Some("SB_PASS".to_string()),
        };
        let value = serde_json::to_value(&original).unwrap();
        assert_eq!(value["username_env"], "SB_USER");
        assert_eq!(value["password_env"], "SB_PASS");

        let roundtrip: Credentials = serde_json::from_value(value).unwrap();
        assert_eq!(roundtrip, original);
    }

    #[test]
    fn wp30aq_pin_credentials_owner_is_credentials_rs() {
        let source = include_str!("credentials.rs");
        assert!(
            source.contains("pub struct Credentials")
                && source.contains("RawCredentials::deserialize(deserializer).map(Into::into)"),
            "expected Credentials owner to live in ir/credentials.rs"
        );
    }

    #[test]
    fn wp30aq_pin_mod_rs_only_reexports_credentials() {
        let source = include_str!("mod.rs");
        assert!(
            source.contains("mod credentials;")
                && source.contains("pub use credentials::Credentials;"),
            "expected ir/mod.rs to re-export Credentials from ir/credentials.rs"
        );
        assert!(
            !source.contains("pub struct Credentials"),
            "expected ir/mod.rs to stop owning Credentials"
        );
    }
}
