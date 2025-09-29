use anyhow::Result;
use std::net::IpAddr;
use std::time::Duration;

use hyper::{Body, Client, Method, Request};

fn default_client() -> Client<hyper::client::HttpConnector, Body> {
    Client::new()
}

pub async fn query_doh_once(
    url: &str,
    host: &str,
    qtype: u16,
    timeout_ms: u64,
) -> Result<(Vec<IpAddr>, Option<u32>)> {
    let req_bytes = crate::dns::udp::build_query(host, qtype)?;
    let client = default_client();
    let req = Request::builder()
        .method(Method::POST)
        .uri(url)
        .header("content-type", "application/dns-message")
        .body(Body::from(req_bytes))?;
    let resp =
        tokio::time::timeout(Duration::from_millis(timeout_ms), client.request(req)).await??;
    let status = resp.status();
    if !status.is_success() {
        return Err(anyhow::anyhow!("doh status {}", status));
    }
    let body_bytes = hyper::body::to_bytes(resp.into_body()).await?;
    let (ips, ttl) = crate::dns::udp::parse_answers(&body_bytes, qtype)?;
    Ok((ips, ttl))
}
