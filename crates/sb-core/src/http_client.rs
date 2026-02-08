//! Global HTTP client registry.
//!
//! Provides a global `HttpClient` instance that can be set once at startup
//! by the application layer. This allows sb-core to perform HTTP requests
//! (geo asset downloads, remote rule-set fetching) without directly depending
//! on a specific HTTP client library like reqwest.

use sb_types::ports::http::{HttpClient, HttpRequest, HttpResponse};
use std::sync::OnceLock;

static GLOBAL_HTTP_CLIENT: OnceLock<Box<dyn HttpClient>> = OnceLock::new();

/// Install the global HTTP client. Should be called once at application startup.
///
/// Returns `Err` if a client has already been installed.
pub fn install_http_client(client: Box<dyn HttpClient>) -> Result<(), Box<dyn HttpClient>> {
    GLOBAL_HTTP_CLIENT.set(client)
}

/// Get a reference to the global HTTP client.
///
/// Returns `None` if no client has been installed yet.
pub fn global_http_client() -> Option<&'static dyn HttpClient> {
    GLOBAL_HTTP_CLIENT.get().map(|c| c.as_ref())
}

/// Execute an HTTP request using the global HTTP client.
///
/// Returns an error if no HTTP client has been installed.
pub async fn http_execute(req: HttpRequest) -> Result<HttpResponse, sb_types::CoreError> {
    let client = global_http_client().ok_or_else(|| {
        sb_types::CoreError::Internal { message: "no HTTP client installed; call install_http_client() at startup".into() }
    })?;
    client.execute(req).await
}
