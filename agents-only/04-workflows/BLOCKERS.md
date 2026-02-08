# 阻塞项清单（Blockers）

> **更新频率**：发现阻塞时立即记录

---

## 当前阻塞项

### 🟠 中优先级

| ID | 阻塞项 | 影响范围 | 需要决策 | 状态 |
|----|--------|---------|---------|------|
| B3 | feature flag 互斥关系 | 全局 | 是否重构 features | ⬜ 待分析 |

### 🟡 低优先级

无

---

## 已解决

| ID | 阻塞项 | 解决方案 | 解决日期 |
|----|--------|---------|---------|
| B1 | sb-core 违规依赖定位 | 完成 VIOLATION-LOCATIONS.md：V1-V5 五类违规 64+ 处精确定位 | 2026-02-07 |
| B2 | sb-adapters ↔ sb-core 解耦方案 | 共享契约放 sb-types（已执行：ports/service.rs 新增 Service/Lifecycle/Startable/StartStage） | 2026-02-07 |
| B4 | rustls 非可选化 | L1.2.3: tls/ 基础设施迁移到 sb-tls；L1.2.4: rustls/tokio-rustls 等 5 个 TLS 依赖全部 optional behind `tls_rustls` feature | 2026-02-07 |
| B5 | reqwest 非可选化 | L1.2.1: HttpClient port trait + 全局注册（OnceLock）+ app 层 ReqwestHttpClient 注入 | 2026-02-07 |
| B6 | dial() 内部 sb-core 协议栈委托 | L1.2.2: SSH 用 russh v0.49 重写；L1.2.5: ShadowTLS 用 sb-tls 重写；L1.2.6: TUIC/Hysteria v1/v2 用 quic_util + 协议内联。全部 10 协议 outbound 独立 | 2026-02-07 |

---

## 決策记录

### [已决策] 共享契约归属 (B2)
**问题**: sb-adapters 和 sb-core 都需要某些 trait，放在哪里？
**选项**:
1. 放在 sb-types（推荐）✅ 已选
2. 新建 sb-contract crate
3. 放在 sb-common

**决策**: sb-types — 已有 Port traits 基础，零运行时依赖

### [已决策] rustls 提取方案 (B4) ✅
**问题**: rustls 是 sb-core 的 15 个文件使用的核心 TLS 依赖，无法简单可选化
**选项**:
1. 提取 tls/ 目录到 sb-tls crate，sb-core 通过 trait 抽象使用
2. 将 rustls 保留为 sb-core 必选依赖，接受 Cargo.toml 检查不通过
3. 将 TLS 功能全部 feature-gate（tls_rustls 特性控制所有 TLS 代码）

**决策**: 组合方案 1+3 —
- L1.2.3: 将 danger verifiers、global root store、crypto provider 迁移到 sb-tls
- L1.2.4: rustls/tokio-rustls/rustls-pemfile/webpki-roots/rustls-pki-types 全部 optional behind `tls_rustls` feature
- sb-core tls/ 变为薄委托层，保留 `apply_from_ir()` 桥接 sb-config

### [已决策] reqwest 提取方案 (B5) ✅
**问题**: reqwest 被 supervisor 的 download_file 函数无条件使用于 geo 文件下载
**选项**:
1. 将下载功能提取为独立 crate 或 trait
2. 将 download_file feature-gate 到 router 特性后
3. 保留为必选依赖

**决策**: 选项 1 —
- sb-types 新增 HttpClient port trait（HttpRequest/HttpResponse/HttpMethod）
- sb-core 新增全局注册（OnceLock + install/get/execute 便利函数）
- app 层注入 ReqwestHttpClient 实现
- reqwest 变 optional，behind dns_doh/service_derp features

### [已决策] dial() sb-core 协议栈委托 (B6) ✅
**问题**: hysteria2/tuic/shadowtls/ssh/hysteria 的 adapter dial() 内部仍委托 sb-core 协议栈
**原因**: sb-core 协议实现使用内部工具（`crate::tls::*`, `crate::metrics::*`）
**选项**:
1. 重写 QUIC/SSH/TLS 协议栈在 sb-adapters 中
2. 提取 sb-core 内部 TLS 工具为公共 API，然后内联
3. 保留现状
4. 将 sb-core 协议实现模块化为独立 crate

**决策**: 选项 2 —
- L1.2.3 将 TLS 基础设施迁移到 sb-tls（解锁 adapter 使用）
- L1.2.2 SSH 用 russh v0.49 完全重写
- L1.2.5 ShadowTLS 用 sb-tls 完全重写
- L1.2.6 创建 quic_util 共享模块 + TUIC/Hysteria v1/v2 完全内联
- 结果: 全部 10 协议 outbound dial() 独立于 sb-core 协议栈
- 注意: inbound 仍依赖 sb-core（接受为合法依赖，工作量超大）

