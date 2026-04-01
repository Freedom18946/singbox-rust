use anyhow::{anyhow, Context, Result};
use sb_config::Config;
use std::sync::Arc;
use tracing::{error, info};

use sb_core::outbound::{health as ob_health, OutboundRegistry, OutboundRegistryHandle};
#[cfg(feature = "router")]
use sb_core::router::router_build_index_from_str;

pub use crate::bootstrap_runtime::runtime_shell::Runtime;

/// Build `OutboundRegistry` from `ConfigIR` (minimal: direct/block/http/socks)
///
/// # Strategic Logic / 战略逻辑
/// This function acts as the **Translation Layer** between the Configuration Intermediate Representation (IR)
/// and the concrete Runtime Outbound Registry.
///
/// 此函数充当配置中间表示 (IR) 与具体运行时出站注册表之间的 **转换层**。
///
/// It iterates through the configured outbounds and instantiates the corresponding `OutboundImpl`.
/// Note that complex selectors (like `URLTest`) require a two-pass approach:
/// 1. Instantiate all concrete outbounds (Direct, Socks, etc.).
/// 2. Instantiate selectors that reference the concrete outbounds.
///
/// 它遍历配置的出站并实例化相应的 `OutboundImpl`。
/// 注意，复杂的选择器（如 `URLTest`）需要两遍扫描的方法：
/// 1. 实例化所有具体出站（Direct, Socks 等）。
/// 2. 实例化引用具体出站的选择器。
#[allow(clippy::too_many_lines, clippy::cognitive_complexity)]
pub fn build_outbound_registry_from_ir(ir: &sb_config::ir::ConfigIR) -> OutboundRegistry {
    let cache_file = ir.experimental.as_ref().and_then(|exp| {
        exp.cache_file.as_ref().map(|cache_cfg| {
            Arc::new(sb_core::services::cache_file::CacheFileService::new(
                cache_cfg,
            )) as Arc<dyn sb_core::context::CacheFile>
        })
    });
    let urltest_history: Arc<dyn sb_core::context::URLTestHistoryStorage> =
        Arc::new(sb_core::services::urltest_history::URLTestHistoryService::new());

    build_outbound_registry_from_ir_with_runtime_services(ir, cache_file, urltest_history)
}

fn build_outbound_registry_from_ir_with_runtime_services(
    ir: &sb_config::ir::ConfigIR,
    cache_file: Option<Arc<dyn sb_core::context::CacheFile>>,
    urltest_history: Arc<dyn sb_core::context::URLTestHistoryStorage>,
) -> OutboundRegistry {
    let mut map = crate::outbound_builder::build_first_pass_concrete_outbounds(ir);

    #[cfg(feature = "router")]
    crate::outbound_groups::bind_selector_outbound_groups(
        ir,
        &mut map,
        cache_file,
        urltest_history,
    );

    // Ensure default aliases exist for router decisions
    crate::outbound_builder::ensure_default_outbound_aliases(&mut map);

    OutboundRegistry::new(map)
}

/// Build a `RouterIndex` from Config using IR rules
///
/// # Errors
/// Returns an error if IR conversion or router index building fails.
#[cfg(feature = "router")]
pub fn build_router_index_from_config(cfg: &Config) -> Result<Arc<sb_core::router::RouterIndex>> {
    let cfg_ir = sb_config::present::to_ir(cfg).map_err(|e| anyhow!("to_ir failed: {e}"))?;
    let text = crate::router_text::ir_to_router_rules_text(&cfg_ir);
    let max_rules =
        crate::bootstrap_runtime::router_helpers::parse_env_usize("SB_ROUTER_RULES_MAX", 100_000);
    let idx = router_build_index_from_str(&text, max_rules)
        .map_err(|e| anyhow!("router index build failed: {e}"))?;
    Ok(idx)
}

/// Start the proxy runtime from configuration.
///
/// # Global Strategic Logic / 全局战略逻辑
/// This is the **Factory Method** of the application. It orchestrates the initialization of the entire proxy system.
/// 这是应用程序的 **工厂方法**。它编排整个代理系统的初始化。
///
/// ## Initialization Sequence / 初始化顺序
/// 1. **Env & Health**: Initialize global proxy health registry and health checks.
///    **环境与健康**: 初始化全局代理健康注册表和健康检查。
/// 2. **Adapter Registration**: Register all available adapters (protocols) to the system.
///    **适配器注册**: 向系统注册所有可用的适配器（协议）。
/// 3. **Config Validation**: Validate the configuration object (strict fail).
///    **配置验证**: 验证配置对象（严格失败）。
/// 4. **IR Conversion**: Convert Config to Intermediate Representation (IR) for efficient processing.
///    **IR 转换**: 将配置转换为中间表示 (IR) 以便高效处理。
/// 5. **DNS Setup**: Apply DNS settings from config.
///    **DNS 设置**: 应用配置中的 DNS 设置。
/// 6. **Outbound Registry**: Build the outbound registry from IR.
///    **出站注册表**: 从 IR 构建出站注册表。
/// 7. **Router Setup**: Initialize the router and install routing rules (Index).
///    **路由设置**: 初始化路由器并安装路由规则 (Index)。
/// 8. **Inbound Startup**: Start all inbound listeners (HTTP, SOCKS, TUN, etc.).
///    **入站启动**: 启动所有入站监听器（HTTP, SOCKS, TUN 等）。
///
/// # Errors
/// Returns an error if:
/// - Configuration validation fails
/// - Proxy registry initialization fails
/// - Inbound/outbound setup fails
/// - Network binding fails
#[allow(clippy::cognitive_complexity)]
pub async fn start_from_config(cfg: Config) -> Result<Runtime> {
    // Install proxy health registry (from default proxy env + proxy pools)
    crate::bootstrap_runtime::proxy_registry::init_proxy_registry_from_env();

    // Start health checking (behind env)
    ob_health::spawn_if_enabled().await;

    #[cfg(feature = "adapters")]
    sb_adapters::register_all();

    // 1) 构建 Registry/Router 并包装成 Handle（严格失败）
    // 1) Build Registry/Router and wrap into Handle (Strict Failure)
    cfg.validate()?; // Configuration validation (IR compiled inside)

    // Convert to IR once
    let cfg_ir =
        Arc::new(sb_config::present::to_ir(&cfg).map_err(|e| anyhow!("to_ir failed: {e}"))?);

    // Initialize CacheFile service (Experiment)
    let cache_service = cfg_ir.experimental.as_ref().and_then(|exp| {
        exp.cache_file.as_ref().map(|cache_cfg| {
            let svc = Arc::new(sb_core::services::cache_file::CacheFileService::new(
                cache_cfg,
            ));

            // Wire to FakeIP persistence
            sb_core::dns::fakeip::set_storage(svc.clone());

            svc as Arc<dyn sb_core::context::CacheFile>
        })
    });

    // Global Context
    let mut ctx = sb_core::context::Context::new();
    if let Some(c) = cache_service.clone() {
        ctx = ctx.with_cache_file(c);
    }
    let urltest_history: Arc<dyn sb_core::context::URLTestHistoryStorage> =
        Arc::new(sb_core::services::urltest_history::URLTestHistoryService::new());
    ctx = ctx.with_urltest_history(urltest_history.clone());

    // Optionally configure DNS via config (env bridge for sb-core)
    crate::bootstrap_runtime::dns_apply::apply_dns_from_config(&cfg);

    // Build outbounds registry from IR (minimal phase 1 set)
    let reg = build_outbound_registry_from_ir_with_runtime_services(
        &cfg_ir,
        cache_service.clone(),
        urltest_history.clone(),
    );
    let oh = Arc::new(OutboundRegistryHandle::new(reg));

    // Validate outbound dependency topology (L2.9)
    let outbound_deps = sb_core::outbound::manager::compute_outbound_deps(&cfg_ir.outbounds);
    let all_tags: Vec<String> = cfg_ir
        .outbounds
        .iter()
        .filter_map(|ob| ob.name.clone())
        .filter(|n| !n.is_empty())
        .collect();
    sb_core::outbound::manager::validate_and_sort(&all_tags, &outbound_deps)
        .map_err(|e| anyhow!("outbound {}", e))?;

    // Resolve default outbound in context (L2.9)
    // Note: this bootstrap path does not auto-inject fallback connectors.
    let default_tag = cfg_ir
        .route
        .final_outbound
        .as_deref()
        .or(cfg_ir.route.default.as_deref());
    if let Some(tag) = default_tag {
        if !tag.is_empty() {
            ctx.outbound_manager
                .set_default(Some(tag.to_string()))
                .await;
        }
    }

    // Create router and install index from IR
    #[cfg(feature = "router")]
    let rh = {
        let handle = crate::bootstrap_runtime::router_helpers::create_router_handle();
        match build_router_index_from_config(&cfg) {
            Ok(idx) => {
                if let Err(e) = handle.replace_index(idx).await {
                    error!(error=%e, "apply router index failed");
                }
            }
            Err(e) => {
                error!(error=%e, "build router index failed");
            }
        }
        handle
    };

    let (inbounds, outbounds, rules) = cfg.stats();
    info!("sb bootstrap: inbounds={inbounds}, outbounds={outbounds}, rules={rules}");

    // 2) 起入站（HTTP / SOCKS / TUN）：每个入站一个 stop 通道；当前不做热更新/回收
    // 2) Start Inbounds (HTTP / SOCKS / TUN): One stop channel per inbound; currently no hot-reload/reclaim
    let inbound_handles = crate::bootstrap_runtime::inbounds::start_inbounds_from_ir(
        &cfg_ir.inbounds,
        #[cfg(feature = "router")]
        &rh,
        &oh,
        #[cfg(feature = "adapters")]
        Arc::new(sb_common::conntrack::ConnTracker::new()),
    );

    // 3) Start experimental services if configured
    // 3) 如果配置了实验性服务则启动
    #[cfg(any(feature = "clash_api", feature = "v2ray_api"))]
    let mut service_handles = Vec::new();
    #[cfg(feature = "clash_api")]
    if let Some(ref exp) = cfg_ir.experimental {
        if let Some(ref clash) = exp.clash_api {
            if let Some(ref listen) = clash.external_controller {
                if let Some(handle) = crate::bootstrap_runtime::api_services::start_clash_api_server(
                    listen.as_str(),
                    clash.secret.clone(),
                    rh.clone(),
                    oh.clone(),
                    cfg_ir.clone(),
                    cache_service.clone(),
                    Some(urltest_history.clone()),
                ) {
                    service_handles.push(handle);
                }
            }
        }
    }

    #[cfg(feature = "v2ray_api")]
    if let Some(ref exp) = cfg_ir.experimental {
        if let Some(ref v2ray) = exp.v2ray_api {
            if let Some(ref listen) = v2ray.listen {
                if let Some(handle) =
                    crate::bootstrap_runtime::api_services::start_v2ray_api_server(listen.as_str())
                {
                    service_handles.push(handle);
                }
            }
        }
    }

    Ok(Runtime {
        #[cfg(feature = "router")]
        router: rh,
        outbounds: oh,
        inbounds: inbound_handles,
        #[cfg(any(feature = "clash_api", feature = "v2ray_api"))]
        services: service_handles,
    })
}
