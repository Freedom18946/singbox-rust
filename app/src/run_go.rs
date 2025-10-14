use anyhow::{anyhow, Result};
use serde_json::Value;
use std::sync::Arc;

use sb_adapters::inbound::http::HttpInbound;
use sb_adapters::inbound::socks::SocksInbound;
use sb_config::{
    ir::ConfigIr,
    present::{self, FormatProfile},
};
use sb_core::pipeline::Inbound;
use sb_core::router::Router;

// 复用 app/lib 提供的构建函数
use crate::{build_router_from_view, collect_outbounds_from_view};

pub async fn run_go1124(ir: &ConfigIr) -> Result<()> {
    // IR -> 规范化视图（Go1124）
    let view: Value = present::to_view(ir, FormatProfile::Go1124);

    // 按视图构建 outbounds + router（保持与现有运行时一致）
    let outs = collect_outbounds_from_view(&view);
    let router: Arc<dyn Router> = build_router_from_view(&view, &outs);

    // 依次挑第一条受支持的入站（先 socks，后 http）；未命中则报错并列出实际类型
    let mut seen = Vec::new();
    for v in &ir.inbounds {
        let ty = v.get("type").and_then(|x| x.as_str()).unwrap_or_default();
        seen.push(ty.to_string());
        match ty {
            "socks" => {
                let inbound = SocksInbound::from_json(v)?.with_router(router.clone());
                inbound.serve().await?;
                return Ok(());
            }
            "http" => {
                let inbound = HttpInbound::from_json(v)?.with_router(router.clone());
                inbound.serve().await?;
                return Ok(());
            }
            _ => {}
        }
    }
    Err(anyhow!(
        "config.inbounds 里未找到受支持的入站（支持：socks, http）。实际类型：{}",
        seen.join(", ")
    ))
}
