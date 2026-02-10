use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::env;
use std::path::{Path, PathBuf};

pub fn resolve_with_env(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(ch) = chars.next() {
        if ch == '$' && chars.peek() == Some(&'{') {
            let _ = chars.next();
            let mut key = String::new();
            while let Some(&next) = chars.peek() {
                let _ = chars.next();
                if next == '}' {
                    break;
                }
                key.push(next);
            }
            if key.is_empty() {
                continue;
            }
            if let Ok(value) = env::var(&key) {
                out.push_str(&value);
            }
            continue;
        }
        out.push(ch);
    }

    out
}

pub fn sha256_hex(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    format!("{:x}", hasher.finalize())
}

pub fn ensure_dir(path: &Path) -> Result<()> {
    std::fs::create_dir_all(path).with_context(|| format!("creating directory {}", path.display()))
}

pub fn canonicalize_or(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}
