//! HTTP client registry (weak-owner model).
//!
//! The application layer installs an `Arc<dyn HttpClient>` via
//! [`install_default_http_client`]; sb-core retains only a `Weak` reference so
//! the client is automatically reclaimed when the owning `Arc` is dropped.
//!
//! There is **no** process-wide hard global singleton.  All callers go through
//! the weak-owner lookup in [`http_execute`].

use sb_types::ports::http::{HttpClient, HttpRequest, HttpResponse};
use std::sync::{Arc, LazyLock, Mutex, Weak};

static DEFAULT_HTTP_CLIENT: LazyLock<Mutex<Option<Weak<dyn HttpClient>>>> =
    LazyLock::new(|| Mutex::new(None));

/// Install the default HTTP client via a weak compatibility registry.
///
/// The caller keeps the returned `Arc` as the explicit owner while `sb-core`
/// only stores a `Weak` lookup entry for compatibility.
#[must_use]
pub fn install_default_http_client(client: Arc<dyn HttpClient>) -> Arc<dyn HttpClient> {
    let mut slot = DEFAULT_HTTP_CLIENT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    match slot.as_ref().and_then(Weak::upgrade) {
        Some(existing) => existing,
        None => {
            *slot = Some(Arc::downgrade(&client));
            client
        }
    }
}

fn current_http_client() -> Option<Arc<dyn HttpClient>> {
    DEFAULT_HTTP_CLIENT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .and_then(Weak::upgrade)
}

/// Execute an HTTP request using the installed HTTP client.
///
/// Returns an error if no client owner is alive.  The caller must ensure
/// [`install_default_http_client`] has been called and the owning `Arc` is
/// still held.
pub async fn http_execute(req: HttpRequest) -> Result<HttpResponse, sb_types::CoreError> {
    let client = current_http_client().ok_or_else(|| sb_types::CoreError::Internal {
        message:
            "no HTTP client installed; call install_default_http_client() at startup and keep the owning Arc alive"
                .into(),
    })?;
    client.execute(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_types::ports::http::{HttpMethod, HttpRequest, HttpResponse};
    use sb_types::CoreError;
    use std::collections::HashMap;
    use std::pin::Pin;

    #[derive(Debug)]
    struct TestHttpClient {
        status: u16,
    }

    impl HttpClient for TestHttpClient {
        fn execute(
            &self,
            req: HttpRequest,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<HttpResponse, CoreError>> + Send + '_>>
        {
            let status = self.status;
            Box::pin(async move {
                Ok(HttpResponse {
                    status,
                    headers: HashMap::from([("x-method".to_string(), format!("{:?}", req.method))]),
                    body: req.url.into_bytes(),
                })
            })
        }
    }

    #[tokio::test]
    async fn weak_default_registry_uses_explicit_owner() {
        let client: Arc<dyn HttpClient> = Arc::new(TestHttpClient { status: 204 });
        let installed = install_default_http_client(client);
        let response = http_execute(HttpRequest {
            method: HttpMethod::Get,
            url: "https://example.invalid/weak-owner".to_string(),
            headers: HashMap::new(),
            body: None,
            timeout_secs: 1,
        })
        .await
        .expect("default http client should execute");
        assert_eq!(response.status, 204);

        drop(installed);

        let err = http_execute(HttpRequest::get("https://example.invalid/missing", 1))
            .await
            .expect_err("dropping explicit owner should disable weak registry lookup");
        match err {
            sb_types::CoreError::Internal { message } => {
                assert!(
                    message.contains("install_default_http_client"),
                    "error should reference the weak-owner API"
                );
                assert!(
                    !message.contains("install_http_client()"),
                    "error must not reference the removed hard-global API"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }

        let replacement: Arc<dyn HttpClient> = Arc::new(TestHttpClient { status: 206 });
        let installed = install_default_http_client(replacement);
        let response = http_execute(HttpRequest::get("https://example.invalid/reinstalled", 1))
            .await
            .expect("replacement http client should execute");
        assert_eq!(response.status, 206);
        drop(installed);
    }
}
