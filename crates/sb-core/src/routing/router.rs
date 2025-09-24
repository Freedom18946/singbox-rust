use anyhow::{Context, Result};
use sb_config::ir::ConfigIR;
use serde_json::Value;
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Default)]
pub struct RouterConfig;

pub struct Router {
    ir: Arc<RwLock<ConfigIR>>,
    matcher: crate::routing::matcher::Matcher,
}

impl Router {
    pub fn new(_config: RouterConfig) -> Result<Self> {
        let default_ir = ConfigIR::default();
        Ok(Self {
            ir: Arc::new(RwLock::new(default_ir)),
            matcher: crate::routing::matcher::Matcher::new(),
        })
    }

    pub async fn reload(&mut self, config_json: &Value) -> Result<()> {
        let new_ir: ConfigIR =
            serde_json::from_value(config_json.clone()).context("Failed to parse JSON to IR")?;
        let mut guard = self.ir.write().await;
        *guard = new_ir;
        self.matcher
            .update(&guard.route)
            .context("Matcher update failed")?;
        Ok(())
    }

    pub async fn route(&self, _req: &str) -> Result<String> {
        let guard = self.ir.read().await;
        // 修复：使用 route.default (Option<String>, outbound tag)
        Ok(guard.route.default.clone().unwrap_or_default())
    }
}
