use crate::context::CacheFile;
use sb_config::ir::CacheFileIR;
use std::path::PathBuf;

/// Cache file service for storing persistent data.
/// 用于存储持久化数据的缓存文件服务。
#[derive(Debug, Clone)]
pub struct CacheFileService {
    enabled: bool,
    path: Option<PathBuf>,
    store_fakeip: bool,
    store_rdrc: bool,
}

impl CacheFileService {
    pub fn new(config: &CacheFileIR) -> Self {
        let path = config.path.as_ref().map(PathBuf::from);
        Self {
            enabled: config.enabled,
            path,
            store_fakeip: config.store_fakeip,
            store_rdrc: config.store_rdrc,
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn path(&self) -> Option<&PathBuf> {
        self.path.as_ref()
    }

    pub fn store_fakeip(&self) -> bool {
        self.store_fakeip
    }

    pub fn store_rdrc(&self) -> bool {
        self.store_rdrc
    }
}

impl CacheFile for CacheFileService {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_file_service() {
        let config = CacheFileIR {
            enabled: true,
            path: Some("/tmp/cache.db".into()),
            store_fakeip: true,
            store_rdrc: false,
            rdrc_timeout: None,
        };

        let svc = CacheFileService::new(&config);
        assert!(svc.enabled());
        assert_eq!(svc.path(), Some(&PathBuf::from("/tmp/cache.db")));
        assert!(svc.store_fakeip());
        assert!(!svc.store_rdrc());
    }
}
