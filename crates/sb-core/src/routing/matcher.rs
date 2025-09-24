use anyhow::Result;
use sb_config::ir::RouteIR;

#[derive(Default)]
pub struct Matcher;

impl Matcher {
    pub fn new() -> Self {
        Self
    }

    pub fn update(&mut self, route: &RouteIR) -> Result<()> {
        // 补全：解析 route.rules 到 matcher 树 (stub)
        if let Some(default) = &route.default {
            println!("Updated matcher default: {}", default);
        }
        for rule in &route.rules {
            println!("Added rule: {:?}", rule);
        }
        Ok(())
    }
}
