#[cfg(all(feature = "router", feature = "dev-cli"))]
use anyhow::Result;
#[cfg(all(feature = "router", feature = "dev-cli"))]
use std::path::Path;

#[cfg(feature = "router")]
#[cfg(feature = "dev-cli")]
pub async fn load_from_path(path: &Path) -> Result<sb_config::Config> {
    Ok(sb_config::Config::load(path)?)
}

#[cfg(not(feature = "router"))]
#[cfg(feature = "dev-cli")]
pub async fn load_from_path(path: &Path) -> Result<sb_config::Config> {
    // minimal 与 router 一致的读法，保持签名不变
    Ok(sb_config::Config::load(path)?)
}

#[cfg(feature = "router")]
#[cfg(feature = "dev-cli")]
pub async fn run_hot_reload(
    _path: &Path,
    /* place holders:
       - inbound/outbound registries
       - router engine handle
       - shutdown signal sender
    */
) -> Result<()> {
    // TODO: 接入真实热加载逻辑：
    // 1) 监听 _path 变更（notify/inotify）
    // 2) 解析为 IR，调用 engine.reload(ir).await
    // 3) 更新桥接/选择器注册表
    Ok(())
}

#[cfg(not(feature = "router"))]
#[cfg(feature = "dev-cli")]
pub async fn run_hot_reload(_path: &Path /* same signature */) -> Result<()> {
    // NOP in minimal mode
    Ok(())
}

/// 仅用于 `--check`：解析并构建 Router/Outbound，不触发任何 IO/监听。
/// 返回 (inbounds, outbounds, rules) 便于主程序打印摘要。
#[cfg(feature = "dev-cli")]
pub fn check_only<P: AsRef<Path>>(path: P) -> Result<(usize, usize, usize)> {
    let cfg = sb_config::Config::load(&path)?;
    cfg.validate()?;
    // 构建以验证引用完整性/默认值语义，但不启动任何任务
    cfg.build_registry_and_router()?; // Stub validation
    Ok((cfg.inbounds.len(), cfg.outbounds.len(), cfg.rules.len()))
}
