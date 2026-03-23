//! Global HTTP client registry.
//!
//! Provides a global `HttpClient` instance that can be set once at startup
//! by the application layer. This allows sb-core to perform HTTP requests
//! (geo asset downloads, remote rule-set fetching) without directly depending
//! on a specific HTTP client library like reqwest.

use sb_types::ports::http::{HttpClient, HttpRequest, HttpResponse};
use std::sync::{Arc, LazyLock, Mutex, OnceLock, Weak};

static GLOBAL_HTTP_CLIENT: OnceLock<Box<dyn HttpClient>> = OnceLock::new();
static DEFAULT_HTTP_CLIENT: LazyLock<Mutex<Option<Weak<dyn HttpClient>>>> =
    LazyLock::new(|| Mutex::new(None));

/// Install the global HTTP client. Should be called once at application startup.
///
/// Returns `Err` if a client has already been installed.
pub fn install_http_client(client: Box<dyn HttpClient>) -> Result<(), Box<dyn HttpClient>> {
    GLOBAL_HTTP_CLIENT.set(client)
}

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

/// Get a reference to the global HTTP client.
///
/// Returns `None` if no client has been installed yet.
pub fn global_http_client() -> Option<&'static dyn HttpClient> {
    GLOBAL_HTTP_CLIENT.get().map(|c| c.as_ref())
}

fn current_http_client() -> Option<Arc<dyn HttpClient>> {
    DEFAULT_HTTP_CLIENT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .as_ref()
        .and_then(Weak::upgrade)
}

/// Execute an HTTP request using the global HTTP client.
///
/// Returns an error if no HTTP client has been installed.
pub async fn http_execute(req: HttpRequest) -> Result<HttpResponse, sb_types::CoreError> {
    if let Some(client) = current_http_client() {
        return client.execute(req).await;
    }

    let client = global_http_client().ok_or_else(|| sb_types::CoreError::Internal {
        message:
            "no HTTP client installed; call install_default_http_client() or install_http_client() at startup"
                .into(),
    })?;
    client.execute(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use sb_types::CoreError;
    use sb_types::ports::http::{HttpMethod, HttpRequest, HttpResponse};
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
                assert!(message.contains("install_default_http_client"));
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
