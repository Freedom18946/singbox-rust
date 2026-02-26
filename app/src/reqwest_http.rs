//! Reqwest-based implementation of the `HttpClient` port trait.
//!
//! This module provides the concrete HTTP client that bridges sb-types' `HttpClient`
//! trait to the reqwest library. It is installed once at application startup.

use sb_types::ports::http::{HttpClient, HttpMethod, HttpRequest, HttpResponse};
use sb_types::CoreError;
use std::pin::Pin;
use std::sync::OnceLock;

/// Reqwest-based HTTP client implementing the `HttpClient` port trait.
pub struct ReqwestHttpClient {
    client: OnceLock<Result<reqwest::Client, String>>,
}

impl ReqwestHttpClient {
    /// Create a new `ReqwestHttpClient`.
    ///
    /// The underlying reqwest client is lazily initialized on first request to
    /// reduce process startup overhead when HTTP is not used.
    #[must_use]
    pub fn new() -> Self {
        Self {
            client: OnceLock::new(),
        }
    }

    fn client(&self) -> Result<&reqwest::Client, CoreError> {
        let result = self.client.get_or_init(|| {
            reqwest::Client::builder()
                .build()
                .map_err(|e| e.to_string())
        });
        match result {
            Ok(client) => Ok(client),
            Err(err) => Err(CoreError::Io {
                class: sb_types::errors::ErrorClass::Io,
                message: format!("failed to initialize HTTP client: {err}"),
            }),
        }
    }
}

impl HttpClient for ReqwestHttpClient {
    fn execute(
        &self,
        req: HttpRequest,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<HttpResponse, CoreError>> + Send + '_>>
    {
        Box::pin(async move {
            let client = self.client()?;

            let method = match req.method {
                HttpMethod::Get => reqwest::Method::GET,
                HttpMethod::Post => reqwest::Method::POST,
                HttpMethod::Put => reqwest::Method::PUT,
                HttpMethod::Delete => reqwest::Method::DELETE,
                HttpMethod::Head => reqwest::Method::HEAD,
            };

            let mut builder = client.request(method, &req.url);

            if req.timeout_secs > 0 {
                builder = builder.timeout(std::time::Duration::from_secs(req.timeout_secs));
            }

            for (key, value) in &req.headers {
                builder = builder.header(key.as_str(), value.as_str());
            }

            if let Some(body) = req.body {
                builder = builder.body(body);
            }

            let response = builder.send().await.map_err(|e| CoreError::Io {
                class: sb_types::errors::ErrorClass::Io,
                message: format!("HTTP request failed: {e}"),
            })?;

            let status = response.status().as_u16();

            let mut headers = std::collections::HashMap::new();
            for (name, value) in response.headers() {
                if let Ok(v) = value.to_str() {
                    headers.insert(name.as_str().to_string(), v.to_string());
                }
            }

            let body = response.bytes().await.map_err(|e| CoreError::Io {
                class: sb_types::errors::ErrorClass::Io,
                message: format!("failed to read response body: {e}"),
            })?;

            Ok(HttpResponse {
                status,
                headers,
                body: body.to_vec(),
            })
        })
    }
}

/// Install the global reqwest HTTP client for sb-core.
///
/// Should be called once at application startup before any HTTP requests are made.
pub fn install_global_http_client() {
    let client = ReqwestHttpClient::new();
    if sb_core::http_client::install_http_client(Box::new(client)).is_err() {
        tracing::debug!("HTTP client already installed, skipping");
    }
}
