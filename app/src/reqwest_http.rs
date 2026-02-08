//! Reqwest-based implementation of the `HttpClient` port trait.
//!
//! This module provides the concrete HTTP client that bridges sb-types' `HttpClient`
//! trait to the reqwest library. It is installed once at application startup.

use sb_types::ports::http::{HttpClient, HttpMethod, HttpRequest, HttpResponse};
use sb_types::CoreError;
use std::pin::Pin;

/// Reqwest-based HTTP client implementing the `HttpClient` port trait.
pub struct ReqwestHttpClient {
    client: reqwest::Client,
}

impl ReqwestHttpClient {
    /// Create a new `ReqwestHttpClient` with default settings.
    pub fn new() -> Result<Self, reqwest::Error> {
        let client = reqwest::Client::builder()
            .build()?;
        Ok(Self { client })
    }
}

impl HttpClient for ReqwestHttpClient {
    fn execute(
        &self,
        req: HttpRequest,
    ) -> Pin<Box<dyn std::future::Future<Output = Result<HttpResponse, CoreError>> + Send + '_>>
    {
        Box::pin(async move {
            let method = match req.method {
                HttpMethod::Get => reqwest::Method::GET,
                HttpMethod::Post => reqwest::Method::POST,
                HttpMethod::Put => reqwest::Method::PUT,
                HttpMethod::Delete => reqwest::Method::DELETE,
                HttpMethod::Head => reqwest::Method::HEAD,
            };

            let mut builder = self.client.request(method, &req.url);

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
                message: format!("HTTP request failed: {}", e),
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
                message: format!("failed to read response body: {}", e),
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
    match ReqwestHttpClient::new() {
        Ok(client) => {
            if sb_core::http_client::install_http_client(Box::new(client)).is_err() {
                tracing::debug!("HTTP client already installed, skipping");
            }
        }
        Err(e) => {
            tracing::warn!("Failed to create reqwest HTTP client: {}", e);
        }
    }
}
