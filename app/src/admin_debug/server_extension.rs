//! App-owned debug routes plugged into sb-api control-plane server.

use crate::admin_debug::{endpoints, http_util::respond_json_error, AdminDebugState};
use sb_api::debug::{DebugRequest, DebugRouteExtension};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Default)]
struct ResponseBuffer(Vec<u8>);

impl AsyncWrite for ResponseBuffer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.0.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for ResponseBuffer {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[async_trait::async_trait]
impl DebugRouteExtension for AdminDebugState {
    async fn handle(&self, request: DebugRequest) -> std::io::Result<Vec<u8>> {
        let mut response = ResponseBuffer::default();
        let method = request.method.as_str();
        let path = request.path.as_str();

        match (method, path) {
            ("GET", "/__health") => endpoints::handle_health(&mut response, self).await?,
            ("GET", "/__metrics") => endpoints::metrics::handle(&mut response, self).await?,
            ("GET", "/__config") => {
                endpoints::handle_config_get_with_state(&mut response, Some(self)).await?;
            }
            ("PUT", "/__config") => {
                endpoints::handle_config_put(
                    &mut response,
                    request.body,
                    &request.headers,
                    Some(self),
                )
                .await?;
            }
            (_, path) if path.starts_with("/router/geoip") => {
                endpoints::handle_geoip(path, &mut response).await?;
            }
            (_, path) if path.starts_with("/router/rules/normalize") => {
                endpoints::handle_normalize(path, &mut response).await?;
            }
            (_, path) if path.starts_with("/subs/") => {
                #[cfg(any(
                    feature = "subs_http",
                    feature = "subs_clash",
                    feature = "subs_singbox"
                ))]
                endpoints::handle_subs_with_metrics(
                    path,
                    &mut response,
                    self.security_metrics_state(),
                )
                .await?;
                #[cfg(not(any(
                    feature = "subs_http",
                    feature = "subs_clash",
                    feature = "subs_singbox"
                )))]
                respond_json_error(
                    &mut response,
                    501,
                    "subscription features not enabled",
                    Some("enable subs_http, subs_clash, or subs_singbox feature"),
                )
                .await?;
            }
            (_, path) if path.starts_with("/router/analyze") => {
                #[cfg(feature = "sbcore_rules_tool")]
                endpoints::handle_analyze(path, &mut response, self).await?;
                #[cfg(not(feature = "sbcore_rules_tool"))]
                respond_json_error(
                    &mut response,
                    501,
                    "sbcore_rules_tool feature not enabled",
                    Some("enable sbcore_rules_tool feature"),
                )
                .await?;
            }
            (_, path) if path.starts_with("/route/dryrun") => {
                #[cfg(feature = "route_sandbox")]
                endpoints::handle_route_dryrun(path, &mut response).await?;
                #[cfg(not(feature = "route_sandbox"))]
                respond_json_error(
                    &mut response,
                    501,
                    "route_sandbox feature not enabled",
                    Some("enable route_sandbox feature"),
                )
                .await?;
            }
            _ => respond_json_error(&mut response, 404, "endpoint not found", None).await?,
        }

        Ok(response.0)
    }
}

pub fn extension(state: Arc<AdminDebugState>) -> Arc<dyn DebugRouteExtension> {
    state
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn test_state() -> Arc<AdminDebugState> {
        Arc::new(AdminDebugState::new(
            #[cfg(any(feature = "router", feature = "sbcore_rules_tool"))]
            Arc::new(crate::analyze::registry::AnalyzeRegistry::default()),
            crate::admin_debug::breaker::install_default(Arc::new(
                crate::admin_debug::breaker::BreakerStore::from_env(),
            )),
            crate::admin_debug::cache::install_default(Arc::new(
                crate::admin_debug::cache::CacheStore::from_env(),
            )),
            crate::admin_debug::reloadable::install_default(Arc::new(
                crate::admin_debug::reloadable::ReloadableConfigStore::from_env(),
            )),
            crate::admin_debug::security_metrics::install_default(Arc::new(
                crate::admin_debug::security_metrics::SecurityMetricsState::new(),
            )),
            std::time::Instant::now(),
        ))
    }

    #[tokio::test]
    async fn extension_preserves_health_contract() {
        let response = test_state()
            .handle(DebugRequest {
                method: "GET".into(),
                path: "/__health".into(),
                headers: HashMap::new(),
                body: bytes::Bytes::new(),
            })
            .await
            .expect("health response");
        let response = String::from_utf8(response).expect("HTTP response is UTF-8");
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("\"config_version\""));
        assert!(response.contains("\"auth_mode\""));
    }

    #[tokio::test]
    async fn config_put_keeps_audit_and_response_contract() {
        let before = crate::admin_debug::audit::recent(1).len();
        let response = test_state()
            .handle(DebugRequest {
                method: "PUT".into(),
                path: "/__config".into(),
                headers: HashMap::from([("x-role".into(), "admin".into())]),
                body: bytes::Bytes::from_static(b"{\"timeout_ms\":4321}"),
            })
            .await
            .expect("config response");
        let response = String::from_utf8(response).expect("HTTP response is UTF-8");
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        assert!(response.contains("\"applied\":true"));
        assert!(crate::admin_debug::audit::recent(1).len() >= before);
        assert_eq!(
            crate::admin_debug::audit::recent(1)[0].action,
            "config_apply"
        );
    }
}
