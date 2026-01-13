# app crate - 主入口

## 1. 概述

`app` 是 singbox-rust 的主入口 crate，提供：
- 命令行接口 (CLI)
- 服务启动和生命周期管理
- 配置加载和验证
- 日志和遥测初始化

---

## 2. 目录结构

```
app/
├── Cargo.toml              # 470 行，定义 30+ features, 30+ binaries
├── build.rs                # 构建脚本，编译时信息
├── src/
│   ├── main.rs             # 主入口，CLI 路由
│   ├── lib.rs              # 库导出
│   ├── bootstrap.rs        # 服务启动核心 (63KB)
│   ├── config_loader.rs    # 配置加载器
│   ├── inbound_starter.rs  # 入站启动器 (24KB)
│   ├── logging.rs          # 日志初始化 (16KB)
│   ├── panic.rs            # Panic 处理
│   ├── hardening.rs        # 安全加固
│   ├── http_util.rs        # HTTP 工具
│   ├── telemetry.rs        # 遥测初始化
│   ├── tracing_init.rs     # Tracing 初始化
│   ├── redact.rs           # 日志脱敏
│   ├── env_dump.rs         # 环境变量导出
│   ├── util.rs             # 工具函数
│   ├── run_go.rs           # Go 版本兼容
│   │
│   ├── bin/                # 27 个命令行工具
│   │   ├── run.rs          # 主运行命令
│   │   ├── check.rs        # 配置检查
│   │   ├── format.rs       # 配置格式化
│   │   ├── version.rs      # 版本信息
│   │   ├── route.rs        # 路由调试
│   │   ├── route-explain.rs# 路由解释
│   │   ├── dsl.rs          # DSL 工具
│   │   ├── subs.rs         # 订阅工具
│   │   ├── geoip.rs        # GeoIP 工具
│   │   ├── geosite.rs      # GeoSite 工具
│   │   ├── ruleset.rs      # 规则集工具
│   │   ├── tools.rs        # 网络工具
│   │   ├── diag.rs         # 诊断工具
│   │   ├── report.rs       # 报告生成
│   │   ├── metrics-serve.rs# Metrics 服务
│   │   └── ...             # 更多工具
│   │
│   ├── cli/                # CLI 模块 (31 个文件)
│   │   ├── mod.rs          # CLI 主模块
│   │   ├── run.rs          # run 子命令
│   │   ├── check.rs        # check 子命令
│   │   └── ...
│   │
│   ├── admin_debug/        # 管理调试模块 (30 个文件)
│   │   ├── mod.rs
│   │   ├── server.rs       # HTTP 服务器
│   │   ├── routes.rs       # 路由定义
│   │   └── ...
│   │
│   ├── analyze/            # 分析模块
│   │   └── ...
│   │
│   └── router/             # 路由桥接
│       └── ...
│
├── tests/                  # 209 个测试
├── examples/               # 12 个示例
└── benches/                # 7 个基准测试
```

---

## 3. 核心文件

### 3.1 main.rs - 入口点

```rust
// app/src/main.rs

fn main() {
    // 1. 初始化 panic 处理
    setup_panic_handler();
    
    // 2. 解析命令行参数
    let cli = Cli::parse();
    
    // 3. 初始化日志
    init_logging(&cli.log_opts)?;
    
    // 4. 构建 Tokio 运行时
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    
    // 5. 运行主逻辑
    runtime.block_on(run(cli))?;
}

async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Run(opts) => run_service(opts).await,
        Command::Check(opts) => check_config(opts).await,
        Command::Format(opts) => format_config(opts).await,
        Command::Version => print_version(),
        // ...
    }
}
```

### 3.2 bootstrap.rs - 服务启动

```rust
// app/src/bootstrap.rs (63KB)

/// 完整的服务启动流程
pub async fn bootstrap_full(
    config: Config,
    opts: BootstrapOpts,
) -> Result<RuntimeHandle> {
    // 1. 环境初始化
    init_environment(&opts)?;
    
    // 2. 加载 GeoIP/GeoSite
    let geo_state = load_geo_state(&config).await?;
    
    // 3. 构建 DNS 系统
    let dns = build_dns_stack(&config, &geo_state)?;
    
    // 4. 构建路由器
    let router = build_router(&config, dns.clone(), geo_state)?;
    
    // 5. 注册出站适配器
    register_outbounds(&config, &router)?;
    
    // 6. 启动入站监听
    let inbound_handles = start_inbounds(&config, router.clone()).await?;
    
    // 7. 启动后台服务
    let service_handles = start_services(&config).await?;
    
    // 8. 启动管理接口
    let admin_handle = start_admin_server(&config, &router).await?;
    
    // 9. 返回运行时句柄
    Ok(RuntimeHandle {
        inbounds: inbound_handles,
        services: service_handles,
        admin: admin_handle,
        router,
        dns,
    })
}
```

### 3.3 inbound_starter.rs - 入站启动

```rust
// app/src/inbound_starter.rs (24KB)

pub async fn start_inbounds(
    config: &Config,
    router: Arc<Router>,
) -> Result<Vec<InboundHandle>> {
    let mut handles = Vec::new();
    
    for inbound_cfg in &config.inbounds {
        let handle = match inbound_cfg.type_name.as_str() {
            "socks" => start_socks_inbound(inbound_cfg, router.clone()).await?,
            "http" => start_http_inbound(inbound_cfg, router.clone()).await?,
            "mixed" => start_mixed_inbound(inbound_cfg, router.clone()).await?,
            "tun" => start_tun_inbound(inbound_cfg, router.clone()).await?,
            "shadowsocks" => start_ss_inbound(inbound_cfg, router.clone()).await?,
            "vmess" => start_vmess_inbound(inbound_cfg, router.clone()).await?,
            "vless" => start_vless_inbound(inbound_cfg, router.clone()).await?,
            "trojan" => start_trojan_inbound(inbound_cfg, router.clone()).await?,
            other => return Err(anyhow!("Unknown inbound type: {}", other)),
        };
        handles.push(handle);
    }
    
    Ok(handles)
}
```

### 3.4 logging.rs - 日志系统

```rust
// app/src/logging.rs (16KB)

pub fn init_logging(opts: &LogOpts) -> Result<()> {
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env()
            .add_directive(opts.level.into()))
        .with_target(true)
        .with_file(true)
        .with_line_number(true);
    
    // JSON 日志格式（可选）
    if opts.json {
        subscriber.json().init();
    } else {
        subscriber.init();
    }
    
    Ok(())
}
```

---

## 4. CLI 命令

### 4.1 主要命令

| 命令 | Binary | 功能 | Feature |
|------|--------|------|---------|
| `run` | `run` | 运行代理服务 | `router` |
| `check` | `check` | 检查配置 | - |
| `format` | `format` | 格式化配置 | - |
| `version` | `version` | 版本信息 | - |

### 4.2 路由工具

| 命令 | Binary | 功能 | Feature |
|------|--------|------|---------|
| `route` | `route` | 路由调试 | `router`, `dsl_analyze`, `dsl_derive` |
| `route-explain` | `route-explain` | 路由解释 | `explain` |
| `sb-explaind` | `sb-explaind` | 解释守护进程 | `router`, `explain` |
| `preview` | `preview` | 预览路由 | `preview_route` |
| `dsl` | `dsl` | DSL 工具 | `router`, `dsl_plus` |

### 4.3 Geo 工具

| 命令 | Binary | 功能 | Feature |
|------|--------|------|---------|
| `geoip` | `geoip` | GeoIP 查询/导出 | `router` |
| `geosite` | `geosite` | GeoSite 查询/导出 | `router` |
| `ruleset` | `ruleset` | 规则集编译 | `router` |

### 4.4 网络工具

| 命令 | Binary | 功能 | Feature |
|------|--------|------|---------|
| `tools` | `tools` | 网络诊断工具 | `tools` |
| `diag` | `diag` | 诊断工具 | `router` |
| `probe-outbound` | `probe-outbound` | 出站探测 | `router` |

### 4.5 观测工具

| 命令 | Binary | 功能 | Feature |
|------|--------|------|---------|
| `metrics-serve` | `metrics-serve` | Metrics HTTP 服务 | `observe` |
| `coverage-http` | `coverage-http` | 规则覆盖率 | `rule_coverage` |
| `sb-rule-coverage` | `sb-rule-coverage` | 规则覆盖率 | `rule_coverage` |

### 4.6 订阅工具

| 命令 | Binary | 功能 | Feature |
|------|--------|------|---------|
| `subs` | `subs` | 订阅管理 | `router` |
| `preflight` | `preflight` | 预检 | `router` |

### 4.7 开发工具

| 命令 | Binary | 功能 | Feature |
|------|--------|------|---------|
| `report` | `report` | 报告生成 | `dev-cli` |
| `sb-bench` | `sb-bench` | 基准测试 | - |
| `sb-udp-echo` | `sb-udp-echo` | UDP 回显测试 | - |
| `handshake` | `handshake` | 握手测试 | `handshake_alpha` |

---

## 5. 管理调试模块

### 5.1 HTTP 端点

```rust
// app/src/admin_debug/routes.rs

pub fn admin_routes() -> Router {
    Router::new()
        // 配置
        .route("/configs", get(get_configs))
        .route("/configs", patch(patch_configs))
        .route("/configs/reload", post(reload_configs))
        
        // 代理
        .route("/proxies", get(list_proxies))
        .route("/proxies/:name", get(get_proxy))
        .route("/proxies/:name", put(set_proxy))
        .route("/proxies/:name/delay", get(test_delay))
        
        // 连接
        .route("/connections", get(list_connections))
        .route("/connections", delete(close_all_connections))
        .route("/connections/:id", delete(close_connection))
        
        // 路由
        .route("/rules", get(list_rules))
        .route("/route/evaluate", post(evaluate_route))
        
        // 订阅
        .route("/subs/fetch", post(fetch_subscription))
        
        // 日志
        .route("/logs", get(stream_logs)) // WebSocket
        
        // 流量
        .route("/traffic", get(stream_traffic)) // WebSocket
        
        // 健康检查
        .route("/health", get(health_check))
}
```

---

## 6. Feature 依赖关系

```
acceptance
├── router ─────────────────────┐
│   ├── sb-core                 │
│   ├── sb-core/router          │
│   ├── sb-core/out_vless       │
│   ├── sb-core/out_vmess       │
│   ├── sb-core/out_trojan      │
│   ├── sb-core/out_hysteria2   │
│   ├── sb-core/out_tuic        │
│   ├── sb-core/v2ray_transport │
│   ├── out_ss                  │
│   └── sb-transport            │
├── tools ──────────────────────┤
│   ├── sb-core                 │
│   ├── reqwest                 │
│   ├── router                  │
│   └── adapters                │
├── observe ────────────────────┤
│   ├── router                  │
│   └── sb-metrics              │
├── admin_debug ────────────────┤
│   ├── observe                 │
│   ├── reqwest                 │
│   ├── subs_http               │
│   ├── admin_envelope          │
│   └── auth                    │
├── schema-v2                   │
├── auth ───────────────────────┤
│   └── admin_envelope          │
├── rate_limit ─────────────────┤
│   └── admin_envelope          │
├── prom                        │
└── preview_route               │
    └── sb-core/preview_route   │
```
