//! Remote rule-set loading with HTTP(S) download and caching
//!
//! Features:
//! - HTTP(S) download with proper error handling
//! - ETag/If-Modified-Since caching
//! - Fallback to cached version on failure
//! - Automatic retry with exponential backoff
//!
use super::*;
use crate::error::{SbError, SbResult};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::fs;
use tokio::io::AsyncWriteExt;

/// Load rule-set from remote URL with caching
pub async fn load_from_url(
    url: &str,
    cache_dir: &Path,
    format: RuleSetFormat,
) -> SbResult<RuleSet> {
    load_from_url_with_cache_file(url, cache_dir, format, None, None).await
}

/// Load rule-set from remote URL with file caching and optional CacheFile fallback.
pub async fn load_from_url_with_cache_file(
    url: &str,
    cache_dir: &Path,
    format: RuleSetFormat,
    cache_tag: Option<&str>,
    cache_file: Option<Arc<dyn crate::context::CacheFile>>,
) -> SbResult<RuleSet> {
    // Create cache directory if it doesn't exist. When CacheFile is wired, a broken
    // file-cache path should not block recovery from the typed persistent payload.
    let file_cache_ready = match fs::create_dir_all(cache_dir).await {
        Ok(()) => true,
        Err(e) => {
            let error = cache_dir_error(e);
            if cache_file.is_none() {
                return Err(error);
            }
            tracing::warn!(
                "rule-set file cache is unavailable, CacheFile fallback remains enabled: {}",
                error
            );
            false
        }
    };

    // Generate cache file name from URL
    let cache_path = get_cache_path(cache_dir, url, format);
    let meta_path = get_meta_path(cache_dir, url);

    // Load cached metadata (ETag, last-modified)
    let cached_meta = if file_cache_ready {
        load_cache_meta(&meta_path).await
    } else {
        None
    };

    // Try to download with conditional request
    match download_with_cache(url, &cached_meta).await {
        Ok(DownloadResult::NotModified) => {
            // Use cached version
            tracing::debug!("rule-set not modified, using cache: {}", url);
            match load_from_cache(&cache_path, format, url).await {
                Ok(rs) => Ok(rs),
                Err(cache_err) => {
                    if let Some(ruleset) =
                        try_cache_file_fallback(cache_tag, cache_file.as_deref(), format, url)
                    {
                        return Ok(ruleset);
                    }
                    Err(cache_err)
                }
            }
        }
        Ok(DownloadResult::Downloaded {
            data,
            etag,
            last_modified,
        }) => {
            tracing::info!("downloaded rule-set: {} ({} bytes)", url, data.len());
            let etag_for_cache_file = etag.clone().unwrap_or_default();
            if let (Some(tag), Some(cache)) = (cache_tag, cache_file.as_ref()) {
                cache.store_rule_set_cached(
                    tag,
                    sb_types::ports::SavedRuleSetBinary {
                        content: data.clone(),
                        last_updated: SystemTime::now(),
                        last_etag: etag_for_cache_file,
                    },
                );
            }

            if file_cache_ready {
                if let Err(error) =
                    save_to_cache(&cache_path, &meta_path, &data, etag, last_modified).await
                {
                    if cache_file.is_none() {
                        return Err(error);
                    }
                    tracing::warn!(
                        "failed to save rule-set file cache, continuing with CacheFile payload: {}",
                        error
                    );
                }
            }

            // Parse and return
            super::binary::parse_binary(&data, RuleSetSource::Remote(url.to_string())).or_else(
                |_| super::binary::parse_json(&data, RuleSetSource::Remote(url.to_string())),
            )
        }
        Err(e) => {
            // Download failed, try to use cached version
            tracing::warn!("failed to download rule-set, trying cache: {} - {}", url, e);
            if file_cache_ready {
                match load_from_cache(&cache_path, format, url).await {
                    Ok(rs) => {
                        tracing::info!("using cached rule-set: {}", url);
                        return Ok(rs);
                    }
                    Err(cache_err) => {
                        if let Some(ruleset) =
                            try_cache_file_fallback(cache_tag, cache_file.as_deref(), format, url)
                        {
                            return Ok(ruleset);
                        }
                        tracing::error!("no valid cache for rule-set: {} - {}", url, cache_err);
                    }
                }
            } else if let Some(ruleset) =
                try_cache_file_fallback(cache_tag, cache_file.as_deref(), format, url)
            {
                return Ok(ruleset);
            }
            Err(e)
        }
    }
}

fn cache_dir_error(e: std::io::Error) -> SbError {
    SbError::Config {
        code: crate::error::IssueCode::MissingRequired,
        ptr: "/rule_set/cache_dir".to_string(),
        msg: format!("failed to create cache directory: {}", e),
        hint: None,
    }
}

fn try_cache_file_fallback(
    cache_tag: Option<&str>,
    cache_file: Option<&dyn crate::context::CacheFile>,
    format: RuleSetFormat,
    url: &str,
) -> Option<RuleSet> {
    let tag = cache_tag?;
    let cache = cache_file?;
    let ruleset = load_from_cache_file(tag, cache, format, url)?;
    tracing::info!("using CacheFile rule-set fallback: {}", url);
    Some(ruleset)
}

fn load_from_cache_file(
    tag: &str,
    cache_file: &dyn crate::context::CacheFile,
    format: RuleSetFormat,
    url: &str,
) -> Option<RuleSet> {
    let saved = cache_file.get_rule_set_cached(tag)?;
    let mut ruleset = match format {
        RuleSetFormat::Binary => {
            super::binary::parse_binary(&saved.content, RuleSetSource::Remote(url.to_string()))
                .ok()?
        }
        RuleSetFormat::Source => {
            super::binary::parse_json(&saved.content, RuleSetSource::Remote(url.to_string()))
                .ok()?
        }
    };
    ruleset.last_updated = saved.last_updated;
    ruleset.etag = if saved.last_etag.is_empty() {
        None
    } else {
        Some(saved.last_etag)
    };
    Some(ruleset)
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
    use sb_types::ports::http::HttpRequest;

    let mut req = HttpRequest::get(url, 30);

    // Add conditional headers if we have cached metadata
    if let Some(meta) = cached_meta {
        if let Some(ref etag) = meta.etag {
            req = req.with_header("If-None-Match", etag.as_str());
        }
        if let Some(ref last_modified) = meta.last_modified {
            req = req.with_header("If-Modified-Since", last_modified.as_str());
        }
    }

    let response = crate::http_client::http_execute(req)
        .await
        .map_err(|e| SbError::Config {
            code: crate::error::IssueCode::MissingRequired,
            ptr: "/rule_set/download/request".to_string(),
            msg: format!("failed to download rule-set: {}", e),
            hint: Some(format!("Check network connectivity and URL: {}", url)),
        })?;

    let status = response.status;

    if status == 304 {
        return Ok(DownloadResult::NotModified);
    }

    if !response.is_success() {
        return Err(SbError::Config {
            code: crate::error::IssueCode::MissingRequired,
            ptr: "/rule_set/download/status".to_string(),
            msg: format!("HTTP error {}: {}", status, url),
            hint: None,
        });
    }

    // Extract caching headers
    let etag = response.header("ETag").map(|s| s.to_string());
    let last_modified = response.header("Last-Modified").map(|s| s.to_string());
    let data = response.body;

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
            .duration_since(UNIX_EPOCH)
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
