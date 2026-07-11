//! Authentication middleware for debug control-plane server.

use super::{Middleware, MiddlewareResult, RequestContext};
use crate::debug::server::{check_auth_with_config, AuthConf};

/// Authentication middleware bound to immutable server configuration.
pub struct AuthMiddleware {
    auth: AuthConf,
}

impl AuthMiddleware {
    /// Bind middleware to immutable server authentication configuration.
    #[must_use]
    pub const fn new(auth: AuthConf) -> Self {
        Self { auth }
    }
}

impl Middleware for AuthMiddleware {
    fn process(&self, ctx: &mut RequestContext) -> MiddlewareResult<()> {
        if check_auth_with_config(&ctx.headers, &ctx.path, &self.auth) {
            return Ok(());
        }

        Err(sb_admin_contract::ResponseEnvelope::err(
            sb_admin_contract::ErrorKind::Auth,
            "Authentication required",
        )
        .with_request_id(&ctx.request_id))
    }
}
