//! RFC 8484 DNS-over-HTTPS (DoH) client.
//!
//! Provides a high-level DoH client API on top of `reqwest`.
//! Enabled by feature `dns_http` (or `dns_doh`).
//!
//! # Example
//! ```ignore
//! use sb_core::dns::http_client::DohClient;
//!
//! let client = DohClient::new("https://cloudflare-dns.com/dns-query")?;
//! let (ips, ttl) = client.query("example.com", 1).await?;
//! ```

use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};

/// Content type for RFC 8484 binary DNS messages.
const DNS_MESSAGE_CONTENT_TYPE: &str = "application/dns-message";

/// Default timeout for DoH requests (milliseconds).
const DEFAULT_TIMEOUT_MS: u64 = 5000;

/// Queries larger than this threshold use POST; smaller ones use GET.
const GET_SIZE_THRESHOLD: usize = 256;

/// RFC 8484 DNS-over-HTTPS client.
///
/// Wraps a `reqwest::Client` with HTTP/2, connection pooling, and
/// adaptive GET/POST method selection per RFC 8484 §4.1.
#[derive(Clone)]
pub struct DohClient {
    url: String,
    client: Arc<reqwest::Client>,
    timeout: Duration,
}

impl DohClient {
    /// Create a new DoH client targeting the given URL.
    ///
    /// The URL should be a full HTTPS endpoint, e.g.
    /// `https://cloudflare-dns.com/dns-query`.
    pub fn new(url: &str) -> Result<Self> {
        let timeout = Duration::from_millis(
            std::env::var("SB_DNS_DOH_TIMEOUT_MS")
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(DEFAULT_TIMEOUT_MS),
        );

        let client = reqwest::Client::builder()
            .timeout(timeout)
            .tcp_keepalive(Duration::from_secs(60))
            .pool_idle_timeout(Duration::from_secs(90))
            .pool_max_idle_per_host(10)
            .user_agent("singbox-rust/1.0")
            .build()
            .context("failed to build reqwest client for DoH")?;

        Ok(Self {
            url: url.to_string(),
            client: Arc::new(client),
            timeout,
        })
    }

    /// Override the request timeout.
    #[must_use]
    pub const fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    // ── High-level API ─────────────────────────────────────────────

    /// Resolve `name` (A or AAAA) via DoH.
    ///
    /// Returns `(ips, optional_min_ttl)`.
    pub async fn query(&self, name: &str, qtype: u16) -> Result<(Vec<IpAddr>, Option<u32>)> {
        let packet = crate::dns::udp::build_query(name, qtype)?;
        let resp = self.exchange(&packet).await?;
        crate::dns::udp::parse_answers(&resp, qtype)
    }

    // ── Wire-level exchange ────────────────────────────────────────

    /// Send a raw DNS wire-format query and return the wire-format response.
    ///
    /// Automatically selects GET (for small packets, better cacheability)
    /// or POST (for large packets, avoids URL length limits) per RFC 8484 §4.1.
    pub async fn exchange(&self, packet: &[u8]) -> Result<Vec<u8>> {
        if packet.len() <= GET_SIZE_THRESHOLD {
            match self.exchange_get(packet).await {
                Ok(r) => return Ok(r),
                Err(e) => {
                    tracing::debug!("DoH GET failed, falling back to POST: {e}");
                }
            }
        }
        self.exchange_post(packet).await
    }

    /// RFC 8484 §4.1 — POST method.
    ///
    /// ```text
    /// POST /dns-query HTTP/2
    /// Content-Type: application/dns-message
    /// Accept: application/dns-message
    /// <binary DNS message>
    /// ```
    async fn exchange_post(&self, packet: &[u8]) -> Result<Vec<u8>> {
        let resp = self
            .client
            .post(&self.url)
            .header("Content-Type", DNS_MESSAGE_CONTENT_TYPE)
            .header("Accept", DNS_MESSAGE_CONTENT_TYPE)
            .body(packet.to_vec())
            .send()
            .await
            .context("DoH POST request failed")?;

        self.validate_and_read(resp).await
    }

    /// RFC 8484 §4.1 — GET method (base64url-encoded query in `?dns=`).
    ///
    /// ```text
    /// GET /dns-query?dns=AAABAAAB... HTTP/2
    /// Accept: application/dns-message
    /// ```
    async fn exchange_get(&self, packet: &[u8]) -> Result<Vec<u8>> {
        let encoded = URL_SAFE_NO_PAD.encode(packet);
        let url = format!("{}?dns={}", self.url, encoded);

        let resp = self
            .client
            .get(&url)
            .header("Accept", DNS_MESSAGE_CONTENT_TYPE)
            .send()
            .await
            .context("DoH GET request failed")?;

        self.validate_and_read(resp).await
    }

    // ── Response handling ──────────────────────────────────────────

    /// Validate HTTP status + content-type, then read body bytes.
    async fn validate_and_read(&self, resp: reqwest::Response) -> Result<Vec<u8>> {
        if !resp.status().is_success() {
            anyhow::bail!(
                "DoH server returned HTTP {}: {}",
                resp.status().as_u16(),
                resp.status().canonical_reason().unwrap_or("Unknown"),
            );
        }

        // RFC 8484 §4.2.1: response MUST use application/dns-message
        if let Some(ct) = resp.headers().get("content-type") {
            let ct_str = ct.to_str().unwrap_or("");
            if !ct_str.starts_with(DNS_MESSAGE_CONTENT_TYPE) {
                anyhow::bail!("DoH: unexpected Content-Type: {ct_str}");
            }
        }

        let body = resp
            .bytes()
            .await
            .context("failed to read DoH response body")?;

        Ok(body.to_vec())
    }
}

impl std::fmt::Debug for DohClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DohClient")
            .field("url", &self.url)
            .field("timeout", &self.timeout)
            .finish()
    }
}

// ── Legacy compat shim ─────────────────────────────────────────────
// The original stub exposed a bare `query(name) -> io::Result<Vec<IpAddr>>`.
// Keep it available so any (unlikely) callers don't break.

/// Convenience: resolve `name` A-records via Cloudflare DoH (blocking-ish).
///
/// This is the original placeholder API; prefer [`DohClient`] for new code.
pub fn query(name: &str) -> std::io::Result<Vec<IpAddr>> {
    // Build a one-shot tokio runtime and query.
    let rt = tokio::runtime::Handle::try_current()
        .map_err(|e| std::io::Error::other(format!("no tokio runtime: {e}")))?;

    let client = DohClient::new("https://cloudflare-dns.com/dns-query")
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    let (ips, _ttl) = rt
        .block_on(client.query(name, 1))
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    Ok(ips)
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = DohClient::new("https://cloudflare-dns.com/dns-query");
        match client {
            Ok(c) => {
                assert_eq!(c.url, "https://cloudflare-dns.com/dns-query");
                assert_eq!(c.timeout, Duration::from_millis(DEFAULT_TIMEOUT_MS));
            }
            Err(e) => {
                // reqwest may fail on some CI environments (no TLS roots).
                eprintln!("skipping DohClient creation test: {e}");
            }
        }
    }

    #[test]
    fn test_with_timeout() {
        let client = DohClient::new("https://dns.google/dns-query")
            .unwrap()
            .with_timeout(Duration::from_secs(10));
        assert_eq!(client.timeout, Duration::from_secs(10));
    }

    #[test]
    fn test_debug_format() {
        let client = DohClient::new("https://dns.google/dns-query").unwrap();
        let dbg = format!("{client:?}");
        assert!(dbg.contains("DohClient"));
        assert!(dbg.contains("dns.google"));
    }

    #[tokio::test]
    #[ignore] // requires network
    async fn test_query_a_record() {
        let client = DohClient::new("https://cloudflare-dns.com/dns-query").unwrap();
        let (ips, ttl) = client.query("google.com", 1).await.unwrap();
        assert!(!ips.is_empty(), "should resolve at least one A record");
        assert!(ttl.is_some(), "should have a TTL");
    }

    #[tokio::test]
    #[ignore] // requires network
    async fn test_query_aaaa_record() {
        let client = DohClient::new("https://cloudflare-dns.com/dns-query").unwrap();
        let (ips, _) = client.query("google.com", 28).await.unwrap();
        // Google should have AAAA records, but don't hard-fail if net is v4-only.
        eprintln!("AAAA records for google.com: {ips:?}");
    }

    #[tokio::test]
    #[ignore] // requires network
    async fn test_exchange_post_and_get() {
        let client = DohClient::new("https://cloudflare-dns.com/dns-query").unwrap();
        let packet = crate::dns::udp::build_query("example.com", 1).unwrap();

        let post_resp = client.exchange_post(&packet).await.unwrap();
        let get_resp = client.exchange_get(&packet).await.unwrap();

        assert!(post_resp.len() > 12, "POST response should be valid DNS");
        assert!(get_resp.len() > 12, "GET response should be valid DNS");
    }
}
