//! DnsHandle：与 RouterHandle 相同的"快照替换"句柄，用于热更新
use std::sync::Arc;
use tokio::sync::RwLock;

use super::DnsRouter;

#[derive(Clone)]
pub struct DnsHandle(pub Arc<RwLock<Arc<DnsRouter>>>);

impl DnsHandle {
    pub fn new(router: DnsRouter) -> Self {
        Self(Arc::new(RwLock::new(Arc::new(router))))
    }
    /// 获取只读快照
    pub async fn snapshot(&self) -> Arc<DnsRouter> {
        self.0.read().await.clone()
    }
    /// 原子替换（热更新）
    pub async fn replace(&self, new_router: DnsRouter) {
        let mut guard = self.0.write().await;
        *guard = Arc::new(new_router);
    }
}