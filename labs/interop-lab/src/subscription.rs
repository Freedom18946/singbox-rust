use crate::case_spec::SubscriptionInputSpec;
use crate::snapshot::SubscriptionResult;
use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value};
use std::collections::BTreeSet;
use tokio::process::Command;

const BROWSER_UA: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
                          (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";

pub async fn parse_subscription(input: &SubscriptionInputSpec) -> Result<SubscriptionResult> {
    let (source_type, raw) = match input {
        SubscriptionInputSpec::Inline { content } => ("inline".to_string(), content.clone()),
        SubscriptionInputSpec::File { path } => {
            let content = tokio::fs::read_to_string(path)
                .await
                .with_context(|| format!("reading subscription file {}", path.display()))?;
            ("file".to_string(), content)
        }
        SubscriptionInputSpec::Http { url } => {
            let body = fetch_subscription_http(url).await?;
            ("http".to_string(), body)
        }
    };

    parse_subscription_content(&source_type, &raw)
}

async fn fetch_subscription_http(url: &str) -> Result<String> {
    let client = reqwest::Client::builder()
        .user_agent(BROWSER_UA)
        .build()
        .with_context(|| "building subscription http client")?;

    let response = client
        .get(url)
        .header(reqwest::header::ACCEPT, "*/*")
        .send()
        .await
        .with_context(|| format!("requesting subscription URL {url}"))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .with_context(|| format!("reading subscription body from {url}"))?;

    if status.is_success() && !looks_like_html(&body) {
        return Ok(body);
    }

    let output = Command::new("curl")
        .arg("-sSL")
        .arg("-A")
        .arg(BROWSER_UA)
        .arg(url)
        .output()
        .await
        .with_context(|| "executing curl fallback for subscription fetch")?;
    if !output.status.success() {
        return Err(anyhow!(
            "subscription fetch failed: reqwest_status={} curl_status={}",
            status,
            output.status
        ));
    }

    let body = String::from_utf8(output.stdout)
        .with_context(|| "curl fallback returned non-utf8 subscription payload")?;
    if body.trim().is_empty() {
        return Err(anyhow!("subscription body empty after curl fallback"));
    }
    Ok(body)
}

fn looks_like_html(body: &str) -> bool {
    let trimmed = body.trim_start();
    trimmed.starts_with("<!DOCTYPE") || trimmed.starts_with("<html") || trimmed.starts_with("<HTML")
}

fn parse_subscription_content(source_type: &str, raw: &str) -> Result<SubscriptionResult> {
    // Guard: empty or whitespace-only input is unsupported
    if raw.trim().is_empty() {
        return Err(anyhow!("unsupported subscription format"));
    }

    if let Ok(value) = serde_json::from_str::<Value>(raw) {
        if let Some(outbounds) = value.get("outbounds").and_then(Value::as_array) {
            let protocols = extract_json_protocols(outbounds);
            let count = outbounds.len();
            return Ok(SubscriptionResult {
                source_type: source_type.to_string(),
                success: true,
                format: "json_outbounds".to_string(),
                node_count: count,
                filtered_node_count: count,
                protocols,
                detail: json!({ "outbounds": count }),
            });
        }
    }

    if let Ok(yaml) = serde_yaml::from_str::<serde_yaml::Value>(raw) {
        if let Some(proxies) = yaml
            .as_mapping()
            .and_then(|map| map.get(serde_yaml::Value::String("proxies".to_string())))
            .and_then(serde_yaml::Value::as_sequence)
        {
            let mut protocols = BTreeSet::new();
            for proxy in proxies {
                if let Some(kind) = proxy
                    .as_mapping()
                    .and_then(|m| m.get(serde_yaml::Value::String("type".to_string())))
                    .and_then(serde_yaml::Value::as_str)
                {
                    protocols.insert(kind.to_string());
                }
            }
            let node_count = proxies.len();
            return Ok(SubscriptionResult {
                source_type: source_type.to_string(),
                success: true,
                format: "yaml_proxies".to_string(),
                node_count,
                filtered_node_count: node_count,
                protocols: protocols.into_iter().collect(),
                detail: json!({ "proxies": node_count }),
            });
        }
    }

    if let Ok(decoded) = STANDARD.decode(raw.trim()) {
        if let Ok(text) = String::from_utf8(decoded) {
            // Guard: avoid infinite recursion if decoded text is same as input or empty
            if !text.is_empty() && text != raw {
                let decoded_res = parse_subscription_content(source_type, &text)?;
                return Ok(SubscriptionResult {
                    format: format!("base64:{}", decoded_res.format),
                    ..decoded_res
                });
            }
        }
    }

    let (protocols, node_count) = parse_link_protocols(raw);
    if protocols.is_empty() {
        return Err(anyhow!("unsupported subscription format"));
    }

    Ok(SubscriptionResult {
        source_type: source_type.to_string(),
        success: true,
        format: "link_lines".to_string(),
        node_count,
        filtered_node_count: node_count,
        protocols,
        detail: json!({ "lines": node_count }),
    })
}

fn extract_json_protocols(outbounds: &[Value]) -> Vec<String> {
    let mut protocols = BTreeSet::new();
    for outbound in outbounds {
        if let Some(kind) = outbound.get("type").and_then(Value::as_str) {
            protocols.insert(kind.to_string());
        }
    }
    protocols.into_iter().collect()
}

fn parse_link_protocols(raw: &str) -> (Vec<String>, usize) {
    let mut out = BTreeSet::new();
    let mut count = 0usize;

    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((scheme, _rest)) = line.split_once("://") {
            let scheme = scheme.trim();
            if !scheme.is_empty() {
                count += 1;
                out.insert(scheme.to_string());
            }
        }
    }
    (out.into_iter().collect(), count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn parse_json_outbounds() {
        let input = SubscriptionInputSpec::Inline {
            content: r#"{"outbounds":[{"type":"vmess"},{"type":"trojan"}]}"#.to_string(),
        };

        let result = parse_subscription(&input).await;
        assert!(result.is_ok());

        if let Ok(snapshot) = result {
            assert_eq!(snapshot.format, "json_outbounds");
            assert_eq!(snapshot.node_count, 2);
        }
    }

    #[tokio::test]
    async fn parse_yaml_proxies() {
        let input = SubscriptionInputSpec::Inline {
            content: "proxies:\n  - {name: a, type: ss}\n  - {name: b, type: vmess}\n".to_string(),
        };

        let result = parse_subscription(&input).await;
        assert!(result.is_ok());

        if let Ok(snapshot) = result {
            assert_eq!(snapshot.format, "yaml_proxies");
            assert_eq!(snapshot.node_count, 2);
        }
    }

    #[tokio::test]
    async fn parse_malformed_json_returns_error() {
        let input = SubscriptionInputSpec::Inline {
            content: r#"{"outbounds": [{"type": }]}"#.to_string(),
        };
        let result = parse_subscription(&input).await;
        assert!(result.is_err(), "malformed JSON should return error");
    }

    #[tokio::test]
    async fn parse_truncated_base64_returns_error() {
        // This is not valid base64 and not valid as any other format either
        let input = SubscriptionInputSpec::Inline {
            content: "!!!TOTALLY_INVALID_BASE64$$$\n".to_string(),
        };
        let result = parse_subscription(&input).await;
        assert!(result.is_err(), "truncated/invalid base64 should return error");
    }

    #[tokio::test]
    async fn parse_empty_string_returns_error() {
        let input = SubscriptionInputSpec::Inline {
            content: "".to_string(),
        };
        let result = parse_subscription(&input).await;
        assert!(result.is_err(), "empty string should return error");
    }

    #[tokio::test]
    async fn parse_link_with_unknown_scheme() {
        let input = SubscriptionInputSpec::Inline {
            content: "foo://host:1234\nbar://example.com:5678#tag1\n".to_string(),
        };
        let result = parse_subscription(&input).await;
        assert!(result.is_ok(), "unknown schemes should still be parseable as link_lines");
        if let Ok(snapshot) = result {
            assert_eq!(snapshot.format, "link_lines");
            assert_eq!(snapshot.node_count, 2);
            assert!(snapshot.protocols.contains(&"foo".to_string()));
            assert!(snapshot.protocols.contains(&"bar".to_string()));
        }
    }

    #[tokio::test]
    async fn parse_yaml_without_proxies_key() {
        let input = SubscriptionInputSpec::Inline {
            content: "servers:\n  - {name: a, type: ss}\n".to_string(),
        };
        let result = parse_subscription(&input).await;
        // YAML without 'proxies' key should not parse as yaml_proxies
        assert!(result.is_err(), "YAML without 'proxies' key should fail");
    }
}
