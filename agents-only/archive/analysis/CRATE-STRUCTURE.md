# Crate 结构分析（Crate Structure Analysis）

> **分析日期**：2026-02-07（L1.3 后更新）
> **分析工具**：手工 + find/wc/grep
> **分析对象**：sb-core 深度分析 + 全 workspace 概览

---

## sb-core 深度分析

**总文件数**：269 .rs 文件（L1.3 清理后，从 280 减少）

### 子目录统计（按代码行数降序）

> ⚠️ L1 架构整固后 outbound/ 已大幅缩减：8 个协议实现移除（~256KB），42 个文件保留。
> services/ 的 web 框架依赖已全部 optional 化。tls/ 变为 sb-tls 薄委托层。

| 子目录 | 文件数 | 状态 | 说明 |
|--------|-------|------|------|
| outbound/ | 42 (原54) | ✅ 已清理 | 8 协议移除，保留管理/调度/hysteria-inbound |
| router/ | 50 | 保留 | 正确归属 |
| dns/ | 40 | 保留 | TLS 引用已 feature-gate |
| services/ | 19 | optional | axum/tonic/hyper 全部 optional |
| runtime/ | 5 | 保留 | switchboard 1918→724 行 |
| inbound/ | 10 | 保留 | 合法架构依赖 |
| net/ | 14 | 保留 | - |
| endpoint/ | 4 | 保留 | 合法架构依赖 |
| metrics/ | 13 | 保留 | 待 MetricsPort 抽象 |
| adapter/ | 5 | 保留 | 适配器接口层 |
| tls/ | 4 | ✅ 薄委托 | 委托到 sb-tls |
| transport/ | 4 | ✅ feature-gated | behind tls_rustls |
| 其他 | ~59 | 保留 | routing/geoip/config/util/... |

### 顶层文件统计

| 文件 | 行数 | 说明 |
|------|------|------|
| context.rs | 931 | 连接上下文（InboundContext 等） |
| error.rs | 455 | 错误类型定义 |
| types.rs | 355 | 内部类型 |
| service.rs | 332 | Service trait 定义 |
| pointer.rs | 300 | 智能指针封装 |
| test_integration.rs | 297 | 集成测试 |
| telemetry.rs | 237 | 遥测 |
| adapter_error.rs | 229 | 适配器错误 |
| udp_nat_instrument.rs | 136 | UDP NAT 工具 |
| lib.rs | 116 | crate 入口 |
| pipeline.rs | 87 | 处理管线 |
| session.rs | 64 | 会话 |
| testutil.rs | 48 | 测试工具 |
| socks.rs | 35 | SOCKS 辅助 |
| http.rs | 18 | HTTP 辅助 |
| error_map.rs | 15 | 错误映射 |

### outbound/ 文件（L1.3 后，42 个文件）

**已移除的协议实现**（~256KB，全部由 sb-adapters 替代）：
- ~~vless.rs, trojan.rs, ssh.rs, shadowtls.rs, wireguard.rs~~
- ~~vmess.rs, vmess/aead.rs~~
- ~~shadowsocks.rs, ss/aead_tcp.rs, ss/aead_udp.rs~~
- ~~tuic.rs, tuic/tests.rs~~

**保留的关键文件**：

| 文件 | 行数 | 内容 | 保留原因 |
|------|------|------|---------|
| mod.rs | 835 | Outbound 调度 | 核心管理逻辑 |
| selector_group.rs | ~800 | 选择器组 | 引擎功能 |
| direct_connector.rs | ~700 | Direct 连接器 | 基础设施 |
| manager.rs | ~600 | Outbound 管理 | 引擎功能 |
| hysteria2.rs | ~1200 | Hysteria2 | 含 inbound 代码 |
| hysteria/v1.rs | ~700 | Hysteria V1 | 含 inbound 代码 |
| naive_h2.rs | ~200 | Naive H2 | 无 sb-adapters 替代 |
| quic/ | ~300 | QUIC 公共 | hysteria inbound 引用 |
| ss/hkdf.rs | ~50 | HKDF 工具 | 公开工具模块 |

### services/ 关键文件

| 文件 | 行数 | 内容 | 迁移目标 |
|------|------|------|---------|
| derp/server.rs | 4,296 | DERP 服务 | sb-platform / sb-adapters |
| ssmapi/server.rs | 822 | SSM API 服务 | sb-api |
| derp/client_registry.rs | 803 | DERP 客户端注册 | sb-platform / sb-adapters |
| v2ray_api.rs | 651 | V2Ray gRPC API | sb-api |
| cache_file.rs | 614 | 缓存文件 | sb-platform |
| ssmapi/user.rs | 417 | 用户管理 | sb-api |
| dns_forwarder.rs | 325 | DNS 转发 | 保留（DNS 子系统） |
| ssmapi/api.rs | 315 | REST API 端点 | sb-api |
| tailscale/coordinator.rs | 308 | Tailscale 协调 | sb-platform |
| ntp.rs | 185 | NTP 时间同步 | sb-platform |

### sb-core Cargo.toml 依赖审计（L1 后）

**内部 sb-* 依赖**：

| 依赖 | 合规？ | 说明 |
|------|--------|------|
| sb-types | ✅ | 契约层，允许 |
| sb-config | ⚠️ | 引擎层应通过 Ports 读取配置 |
| sb-metrics | ⚠️ | 待 MetricsPort 抽象 |
| sb-platform | ⚠️ | 仅 tun feature 使用 |
| sb-tls | ✅ | TLS 委托层（合理依赖方向） |
| sb-transport | ⚠️ | transport 功能需要 |

**外部依赖状态（L1 后）**：

| 依赖 | 状态 | 说明 |
|------|------|------|
| ~~tower~~ | ✅ 已移除 | 零源码引用 |
| hyper | ✅ optional | behind out_naive, service_derp |
| axum | ✅ optional | behind service_ssmapi, service_clash_api |
| tonic | ✅ optional | behind service_v2ray_api |
| rustls + tokio-rustls | ✅ optional | behind tls_rustls |
| quinn | ✅ optional | behind out_quic, dns_doq, dns_doh3 |
| reqwest | ✅ optional | behind dns_doh, service_derp |
| snow | ✅ optional | behind out_wireguard, out_tailscale |
| smoltcp | 保留 | TUN stack（sb-platform 域） |
| tokio-tungstenite | ✅ optional | behind service_derp |

---

## sb-adapters 结构

**文件数**：109

**内部 sb-* 依赖**：

| 依赖 | 合规？ | 说明 |
|------|--------|------|
| sb-types | ✅ | 契约层 |
| sb-config | ⚠️ | 适配器可能需要读配置 IR |
| sb-core | ❌ **严重** | 反向依赖，违反架构规范 |

**sb-core 依赖详情**：
- Cargo.toml: `sb-core = { features = ["router", "scaffold", "v2ray_transport"] }`
- 18 个 feature 直接转发到 sb-core
- 代码中大量 `use sb_core::*` 引用（service, endpoint, dns, outbound 模块）

---

## 全 Workspace Crate 概览

### 叶子节点（无 sb-* 依赖）✅

| Crate | 文件数 | 状态 |
|-------|-------|------|
| sb-types | 10 | ✅ 纯净 |
| sb-metrics | 9 | ✅ 纯净 |
| sb-tls | 21 | ✅ 纯净 |
| sb-platform | 22 | ✅ 纯净 |
| sb-runtime | 17 | ✅ 纯净 |
| sb-security | 5 | ✅ 纯净 |
| sb-common | 10 | ✅ 纯净 |
| sb-admin-contract | 2 | ✅ 纯净 |
| sb-test-utils | 4 | ✅ 纯净 |

### 有依赖节点

| Crate | 文件数 | sb-* 依赖 | 合规？ |
|-------|-------|----------|-------|
| sb-config | 56 | sb-types | ✅ |
| sb-transport | 57 | sb-metrics | ✅ |
| sb-proto | 9 | sb-transport | ✅ |
| sb-core | 269 | sb-config, sb-metrics, sb-platform, sb-tls, sb-types, sb-transport | ⚠️ 已优化（所有外部 web/tls/quic optional） |
| sb-adapters | 109 | sb-config, sb-core(inbound), sb-types, sb-tls | ⚠️ outbound 独立，inbound 合法依赖 |
| sb-api | 29 | sb-config, sb-core | ⚠️ |
| sb-subscribe | 24 | sb-core (optional), sb-common | ✅ sb-core 已 optional |

---

## 量化摘要

| 指标 | L1 前 | L1 后 |
|------|-------|-------|
| sb-core .rs 文件 | 280 | 269 |
| outbound/ 文件 | 54 | 42 |
| outbound/mod.rs 行数 | 1305 | 835 |
| switchboard.rs 行数 | 1918 | 724 |
| 已迁移到 sb-adapters 的协议 | 0 | 10（全部 outbound） |
| 已移除的 legacy 代码 | 0 | ~256KB |
| 边界违规类别 | 7 | 0 |

---

*初始分析：2026-02-07 | 更新：2026-02-07 L1.3 后 | Agent：Claude Code (Opus 4.6)*
