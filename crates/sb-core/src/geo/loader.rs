//! Geo loaders with environment switches (default OFF).
//! - GEOIP_PATH: path to mmdb
//! - GEOSITE_PATH: path to geosite db (text lines)
//! 行为：未配置时返回空集，不阻断主链。
use std::collections::HashSet;
use std::fs;
use std::path::Path;

pub fn load_geoip() -> Option<Vec<u8>> {
    if let Ok(p) = std::env::var("GEOIP_PATH") {
        fs::read(p).ok()
    } else {
        None
    }
}

pub fn load_geosite() -> Option<HashSet<String>> {
    if let Ok(p) = std::env::var("GEOSITE_PATH") {
        let t = fs::read_to_string(p).ok()?;
        let set = t
            .lines()
            .filter_map(|l| {
                let s = l.trim();
                if s.is_empty() || s.starts_with('#') {
                    None
                } else {
                    Some(s.to_string())
                }
            })
            .collect::<HashSet<_>>();
        Some(set)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn load_none_when_env_absent() {
        std::env::remove_var("GEOIP_PATH");
        std::env::remove_var("GEOSITE_PATH");
        assert!(load_geoip().is_none());
        assert!(load_geosite().is_none());
    }
}
