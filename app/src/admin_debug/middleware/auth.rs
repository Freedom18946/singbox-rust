//! Authentication middleware for admin debug HTTP server
//!
//! This middleware wraps the existing `AuthProvider` system and converts
//! authentication failures to contract-compliant `ResponseEnvelope` errors
//! with `ErrorKind::Auth`.

use super::{Middleware, MiddlewareResult, RequestContext};
use crate::admin_debug::auth::{from_config, AuthConfig, AuthError, AuthProvider};

/// Authentication middleware implementation
pub struct AuthMiddleware {
    provider: Box<dyn AuthProvider>,
}

impl AuthMiddleware {
    /// Create auth middleware from configuration
    #[cfg(feature = "auth")]
    pub fn from_config(config: &AuthConfig) -> Result<Self, AuthError> {
        let provider = from_config(config)?;
        Ok(Self { provider })
    }

    /// Create auth middleware when auth feature is disabled
    #[cfg(not(feature = "auth"))]
    pub fn from_config(config: &AuthConfig) -> Result<Self, AuthError> {
        let provider = from_config(config)?;
        Ok(Self { provider })
    }

    /// Create auth middleware from environment configuration
    pub fn from_env() -> Result<Self, AuthError> {
        use crate::admin_debug::http_server::AuthConf;

        let auth_conf = AuthConf::from_env();
        let auth_config = match auth_conf {
            AuthConf::Disabled => AuthConfig::None,
            AuthConf::Bearer { token } => AuthConfig::ApiKey {
                key: token,
                key_id: None,
            },
            AuthConf::Hmac { secret } => AuthConfig::ApiKey {
                key: secret,
                key_id: None,
            },
            AuthConf::BearerAndHmac { token, secret: _ } => {
                // For simplicity, prefer Bearer token
                AuthConfig::ApiKey {
                    key: token,
                    key_id: None,
                }
            }
            AuthConf::Mtls { .. } => AuthConfig::None, // mTLS handled at TLS layer
        };

        Self::from_config(&auth_config)
    }

    /// Create a disabled auth middleware (allows all requests)
    pub fn disabled() -> Result<Self, AuthError> {
        Self::from_config(&AuthConfig::None)
    }
}

impl Middleware for AuthMiddleware {
    fn process(&self, ctx: &mut RequestContext) -> MiddlewareResult<()> {
        match self.provider.check(&ctx.headers, &ctx.path) {
            Ok(()) => {
                tracing::debug!(
                    request_id = %ctx.request_id,
                    path = %ctx.path,
                    target = "admin",
                    "authentication passed"
                );
                Ok(())
            }
            Err(auth_error) => {
                tracing::warn!(
                    request_id = %ctx.request_id,
                    path = %ctx.path,
                    error = %auth_error,
                    target = "admin",
                    "authentication failed"
                );

                // Convert AuthError to contract-compliant error
                let error_body: sb_admin_contract::ErrorBody = auth_error.into();
                let mut envelope =
                    sb_admin_contract::ResponseEnvelope::err(error_body.kind, error_body.msg);

                // Add hint if available
                if let Some(hint) = error_body.hint {
                    if let Some(ref mut err) = envelope.error {
                        err.hint = Some(hint);
                    }
                }

                // Add request ID
                envelope = envelope.with_request_id(&ctx.request_id);

                Err(envelope)
            }
        }
    }
}

/// Helper function to check if authentication is required for a path
#[must_use]
pub fn requires_auth(path: &str) -> bool {
    match path {
        // Protected endpoints that require authentication
        "/__health" | "/__metrics" | "/__config" => true,
        p if p.starts_with("/admin/") => true,

        // Public endpoints (if any)
        p if p.starts_with("/router/geoip") => false,
        p if p.starts_with("/router/rules/normalize") => false,

        // Default to requiring auth for safety
        _ => true,
    }
}

/// Create auth middleware with path-based exemptions
pub struct SelectiveAuthMiddleware {
    auth_middleware: AuthMiddleware,
    exempt_paths: Vec<String>,
}

impl SelectiveAuthMiddleware {
    #[must_use]
    pub fn new(auth_middleware: AuthMiddleware) -> Self {
        Self {
            auth_middleware,
            exempt_paths: vec![
                "/router/geoip".to_string(),
                "/router/rules/normalize".to_string(),
            ],
        }
    }

    #[must_use]
    pub fn with_exempt_paths(mut self, paths: Vec<String>) -> Self {
        self.exempt_paths = paths;
        self
    }

    fn is_exempt(&self, path: &str) -> bool {
        self.exempt_paths
            .iter()
            .any(|exempt| path.starts_with(exempt))
    }
}

impl Middleware for SelectiveAuthMiddleware {
    fn process(&self, ctx: &mut RequestContext) -> MiddlewareResult<()> {
        if self.is_exempt(&ctx.path) {
            tracing::debug!(
                request_id = %ctx.request_id,
                path = %ctx.path,
                target = "admin",
                "path exempt from authentication"
            );
            Ok(())
        } else {
            self.auth_middleware.process(ctx)
        }
    }
}

#[cfg(test)]
#[cfg(feature = "admin_tests")]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn test_requires_auth() {
        assert!(requires_auth("/__health"));
        assert!(requires_auth("/__metrics"));
        assert!(requires_auth("/__config"));
        assert!(requires_auth("/admin/something"));

        assert!(!requires_auth("/router/geoip/test"));
        assert!(!requires_auth("/router/rules/normalize"));

        // Default behavior
        assert!(requires_auth("/unknown/path"));
    }

    #[test]
    fn test_selective_auth_exemptions() {
        let auth_middleware = AuthMiddleware::disabled().unwrap();
        let selective = SelectiveAuthMiddleware::new(auth_middleware);

        assert!(selective.is_exempt("/router/geoip/test"));
        assert!(selective.is_exempt("/router/rules/normalize?param=1"));
        assert!(!selective.is_exempt("/__health"));
        assert!(!selective.is_exempt("/admin/test"));
    }

    #[cfg(feature = "auth")]
    #[test]
    fn test_auth_middleware_creation() {
        let config = AuthConfig::None;
        let middleware = AuthMiddleware::from_config(&config).unwrap();

        let mut ctx = RequestContext::new("GET".to_string(), "/test".to_string(), HashMap::new());

        // None provider should allow all requests
        assert!(middleware.process(&mut ctx).is_ok());
    }

    #[test]
    fn test_auth_middleware_disabled() {
        let middleware = AuthMiddleware::disabled().unwrap();

        let mut ctx = RequestContext::new("GET".to_string(), "/test".to_string(), HashMap::new());

        // Disabled auth should allow all requests
        assert!(middleware.process(&mut ctx).is_ok());
    }

    #[test]
    fn test_selective_auth_middleware() {
        let auth_middleware = AuthMiddleware::disabled().unwrap();
        let selective = SelectiveAuthMiddleware::new(auth_middleware)
            .with_exempt_paths(vec!["/public".to_string()]);

        let mut public_ctx = RequestContext::new(
            "GET".to_string(),
            "/public/test".to_string(),
            HashMap::new(),
        );

        let mut private_ctx = RequestContext::new(
            "GET".to_string(),
            "/private/test".to_string(),
            HashMap::new(),
        );

        // Public path should be exempt
        assert!(selective.process(&mut public_ctx).is_ok());

        // Private path should go through auth (but disabled auth allows it)
        assert!(selective.process(&mut private_ctx).is_ok());
    }
}
