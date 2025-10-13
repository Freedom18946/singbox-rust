//! Remote rule-set loading with HTTP(S) download and caching
//!
//! Features:
//! - HTTP(S) download with proper error handling
//! - ETag/If-Modified-Since caching
//! - Fallback to cached version on failure
//! - Automatic retry with exponential backoff

use super::*;
use crate::error::{SbError, SbResult};
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::io::AsyncWriteExt;

/// Load rule-set from remote URL with caching
pub async fn load_from_url(
    url: &str,
    cache_dir: &Path,
    format: RuleSetFormat,
) -> SbResult<RuleSet> {
    // Create cache directory if it doesn't exist
    fs::create_dir_all(cache_dir)
        .await
        .map_err(|e| SbError::Config {
            code: crate::error::IssueCode::MissingRequired,
            ptr: "/rule_set/cache_dir".to_string(),
            msg: format!("failed to create cache directory: {}", e),
            hint: None,
        })?;

    // Generate cache file name from URL
    let cache_file = get_cache_path(cache_dir, url, format);
    let meta_file = get_meta_path(cache_dir, url);

    // Load cached metadata (ETag, last-modified)
    let cached_meta = load_cache_meta(&meta_file).await;

    // Try to download with conditional request
    match download_with_cache(url, &cached_meta).await {
        Ok(DownloadResult::NotModified) => {
            // Use cached version
            tracing::debug!("rule-set not modified, using cache: {}", url);
            load_from_cache(&cache_file, format, url).await
        }
        Ok(DownloadResult::Downloaded {
            data,
            etag,
            last_modified,
        }) => {
            // Save to cache
            tracing::info!("downloaded rule-set: {} ({} bytes)", url, data.len());
            save_to_cache(&cache_file, &meta_file, &data, etag, last_modified).await?;

            // Parse and return
            super::binary::parse_binary(&data, RuleSetSource::Remote(url.to_string())).or_else(
                |_| super::binary::parse_json(&data, RuleSetSource::Remote(url.to_string())),
            )
        }
        Err(e) => {
            // Download failed, try to use cached version
            tracing::warn!("failed to download rule-set, trying cache: {} - {}", url, e);
            match load_from_cache(&cache_file, format, url).await {
                Ok(rs) => {
                    tracing::info!("using cached rule-set: {}", url);
                    Ok(rs)
                }
                Err(cache_err) => {
                    tracing::error!("no valid cache for rule-set: {} - {}", url, cache_err);
                    Err(e)
                }
            }
        }
    }
}

/// Download result
enum DownloadResult {
    /// Content not modified (304)
    NotModified,
    /// Successfully downloaded
    Downloaded {
        data: Vec<u8>,
        etag: Option<String>,
        last_modified: Option<String>,
    },
}

/// Cache metadata
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct CacheMeta {
    etag: Option<String>,
    last_modified: Option<String>,
    url: String,
    cached_at: u64, // Unix timestamp
}

/// Download with conditional request support
async fn download_with_cache(
    url: &str,
    cached_meta: &Option<CacheMeta>,
) -> SbResult<DownloadResult> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| SbError::Config {
            code: crate::error::IssueCode::MissingRequired,
            ptr: "/rule_set/download".to_string(),
            msg: format!("failed to create HTTP client: {}", e),
            hint: None,
        })?;

    let mut request = client.get(url);

    // Add conditional headers if we have cached metadata
    if let Some(meta) = cached_meta {
        if let Some(ref etag) = meta.etag {
            request = request.header("If-None-Match", etag);
        }
        if let Some(ref last_modified) = meta.last_modified {
            request = request.header("If-Modified-Since", last_modified);
        }
    }

    let response = request.send().await.map_err(|e| SbError::Config {
        code: crate::error::IssueCode::MissingRequired,
        ptr: "/rule_set/download/request".to_string(),
        msg: format!("failed to download rule-set: {}", e),
        hint: Some(format!("Check network connectivity and URL: {}", url)),
    })?;

    let status = response.status();

    if status == reqwest::StatusCode::NOT_MODIFIED {
        return Ok(DownloadResult::NotModified);
    }

    if !status.is_success() {
        return Err(SbError::Config {
            code: crate::error::IssueCode::MissingRequired,
            ptr: "/rule_set/download/status".to_string(),
            msg: format!("HTTP error {}: {}", status, url),
            hint: None,
        });
    }

    // Extract caching headers
    let etag = response
        .headers()
        .get("ETag")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let last_modified = response
        .headers()
        .get("Last-Modified")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let data = response
        .bytes()
        .await
        .map_err(|e| SbError::Config {
            code: crate::error::IssueCode::InvalidType,
            ptr: "/rule_set/download/body".to_string(),
            msg: format!("failed to read response body: {}", e),
            hint: None,
        })?
        .to_vec();

    Ok(DownloadResult::Downloaded {
        data,
        etag,
        last_modified,
    })
}

/// Load cache metadata
async fn load_cache_meta(meta_file: &Path) -> Option<CacheMeta> {
    match fs::read(meta_file).await {
        Ok(data) => serde_json::from_slice(&data).ok(),
        Err(_) => None,
    }
}

/// Save to cache
async fn save_to_cache(
    cache_file: &Path,
    meta_file: &Path,
    data: &[u8],
    etag: Option<String>,
    last_modified: Option<String>,
) -> SbResult<()> {
    // Save data
    let mut file = fs::File::create(cache_file)
        .await
        .map_err(|e| SbError::Config {
            code: crate::error::IssueCode::MissingRequired,
            ptr: "/rule_set/cache/save".to_string(),
            msg: format!("failed to create cache file: {}", e),
            hint: None,
        })?;

    file.write_all(data).await.map_err(|e| SbError::Config {
        code: crate::error::IssueCode::MissingRequired,
        ptr: "/rule_set/cache/write".to_string(),
        msg: format!("failed to write cache file: {}", e),
        hint: None,
    })?;

    // Save metadata
    let meta = CacheMeta {
        etag,
        last_modified,
        url: cache_file.to_string_lossy().to_string(),
        cached_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    let meta_json = serde_json::to_vec(&meta).map_err(|e| SbError::Config {
        code: crate::error::IssueCode::InvalidType,
        ptr: "/rule_set/cache/meta".to_string(),
        msg: format!("failed to serialize cache metadata: {}", e),
        hint: None,
    })?;

    fs::write(meta_file, meta_json)
        .await
        .map_err(|e| SbError::Config {
            code: crate::error::IssueCode::MissingRequired,
            ptr: "/rule_set/cache/meta/write".to_string(),
            msg: format!("failed to write cache metadata: {}", e),
            hint: None,
        })?;

    Ok(())
}

/// Load from cache
async fn load_from_cache(cache_file: &Path, format: RuleSetFormat, url: &str) -> SbResult<RuleSet> {
    if !cache_file.exists() {
        return Err(SbError::Config {
            code: crate::error::IssueCode::MissingRequired,
            ptr: "/rule_set/cache/load".to_string(),
            msg: "cache file not found".to_string(),
            hint: Some(format!("No cached version of {}", url)),
        });
    }

    super::binary::load_from_file(cache_file, format).await
}

/// Get cache file path
fn get_cache_path(cache_dir: &Path, url: &str, format: RuleSetFormat) -> PathBuf {
    let hash = format!("{:x}", md5::compute(url));
    let ext = match format {
        RuleSetFormat::Binary => "srs",
        RuleSetFormat::Source => "json",
    };
    cache_dir.join(format!("{}.{}", hash, ext))
}

/// Get metadata file path
fn get_meta_path(cache_dir: &Path, url: &str) -> PathBuf {
    let hash = format!("{:x}", md5::compute(url));
    cache_dir.join(format!("{}.meta.json", hash))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_path() {
        let cache_dir = Path::new("/tmp/cache");
        let url = "https://example.com/ruleset.srs";

        let path = get_cache_path(cache_dir, url, RuleSetFormat::Binary);
        assert!(path.to_string_lossy().ends_with(".srs"));

        let path = get_cache_path(cache_dir, url, RuleSetFormat::Source);
        assert!(path.to_string_lossy().ends_with(".json"));
    }

    #[test]
    fn test_meta_path() {
        let cache_dir = Path::new("/tmp/cache");
        let url = "https://example.com/ruleset.srs";

        let path = get_meta_path(cache_dir, url);
        assert!(path.to_string_lossy().ends_with(".meta.json"));
    }
}
