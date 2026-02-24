# L11-L14 详细工作包规划

> **状态**: ✅ **全部 Closed** (2026-02-12)
> **执行结果**: 30/30 WP 完成，5 个批次全部通过验收

## 执行结果摘要

| 指标 | 计划 | 实际 |
|------|------|------|
| 总工作包 | 30 | 30 ✅ |
| 新 Rust 源文件 | 3 | 3 (deprecation.rs, auth.rs, cert watcher in global.rs) |
| 新 interop-lab case | 9 | 9 (总计 77) |
| 新单元测试 | 40+ | 95+ (1492 → 1587) |
| workspace 编译 | ✅ | ✅ |
| interop-lab 测试 | ✅ | ✅ 27/27 |

## Context

singbox-rust 项目已完成 L1（架构整固）、L2（功能对齐，acceptance baseline 100% parity）、L5-L7（联测仿真，22/22 WP），L8-L10 基础设施也已全部落地。本计划为 L11~L14 提供执行级工作包设计，覆盖 CI 闭环、迁移治理、服务安全、TLS 高级能力四大主题。

**总量**: 30 工作包，5 个批次（Batch 1-5），可并行执行。

---

## L11: CI 与趋势门禁正式闭环（4 WP）

### L11.1.1 — 规划文档过期文本修正

- **复杂度**: S | **优先级**: P1 | **依赖**: 无
- **内容**: 07-L5-L11-INTEROP-LAB-PLAN.md L11 节仍写"awaiting workflows"，但 CI workflow 已实现。更新文档反映实际状态。
- **文件**: agents-only/03-planning/07-L5-L11-INTEROP-LAB-PLAN.md, agents-only/active_context.md
- **验收**: 文档无"awaiting"字样；L11 状态标记为 complete

### L11.1.2 — 趋势门禁阈值模板配置化

- **复杂度**: M | **优先级**: P1 | **依赖**: 无
- **内容**: nightly workflow 中阈值硬编码。提取到 labs/interop-lab/configs/trend_thresholds.yaml，支持 strict/env_limited 分区。run_case_trend_gate.sh 读取 THRESHOLD_CONFIG 环境变量。
- **文件**: labs/interop-lab/scripts/run_case_trend_gate.sh, labs/interop-lab/configs/trend_thresholds.yaml（新建）, .github/workflows/interop-lab-nightly.yml
- **验收**: 配置文件存在且含 strict/env_limited 节；脚本从文件读取阈值；无配置时回退硬编码默认值

### L11.1.3 — 历史趋势追踪与回归检测

- **复杂度**: M | **优先级**: P2 | **依赖**: L11.1.2
- **内容**: aggregate_trend_report.sh 每次 nightly 追加 trend_history.jsonl（JSONL 格式，带 ISO 时间戳）。检测最近 5 次运行中 strict case score 退化 >10% 时发出 REGRESSION_WARNING。
- **文件**: labs/interop-lab/scripts/aggregate_trend_report.sh, .github/workflows/interop-lab-nightly.yml
- **验收**: history 文件逐行增长；回归检测能识别退化 case；缺失历史文件时从零开始

### L11.1.4 — L11 验收门禁与闭环

- **复杂度**: S | **优先级**: P0 | **依赖**: L11.1.1, L11.1.2
- **内容**: 运行完整 L11 验收：CI smoke 可触发、nightly 端到端可运行、P0 strict 趋势门禁通过。在 active_context 中记录闭环证据。
- **文件**: agents-only/active_context.md, agents-only/03-planning/07-L5-L11-INTEROP-LAB-PLAN.md
- **验收**: cargo test -p interop-lab 通过；nightly YAML 语法合法；L11 标记 "Closed"

---

## L12: 迁移与兼容治理（8 WP）

### L12.1.1 — IssueCode::Deprecated 枚举变体

- **复杂度**: S | **优先级**: P0 | **依赖**: 无
- **内容**: 在 sb-types 的 IssueCode 枚举（当前 27 个变体）中新增 Deprecated。包括 as_str() 映射和序列化兼容。
- **文件**: crates/sb-types/src/lib.rs（IssueCode 枚举 ~L115 + as_str ~L210）
- **验收**: cargo check -p sb-types 通过；IssueCode::Deprecated.as_str() 返回 "Deprecated"；序列化往返正确

### L12.1.2 — 集中化弃用目录模块

- **复杂度**: M | **优先级**: P0 | **依赖**: L12.1.1
- **内容**: 新建 crates/sb-config/src/deprecation.rs。将散落在 ir/mod.rs、model.rs、validator/v2.rs 中的弃用信息集中为 DeprecatedField 结构体数组，字段包括 json_pointer、since_version、replacement、severity、category。初始 ≥8 条记录（WireGuard outbound、model::Config、legacy tag/listen_port/server_port/socks5/outbound rule/flat conditions）。
- **文件**: crates/sb-config/src/deprecation.rs（新建）, crates/sb-config/src/lib.rs
- **验收**: cargo check -p sb-config 通过；≥8 条目录；3+ 单元测试（非空、无重复指针、severity 检查）

### L12.1.3 — 验证器弃用检测 Pass

- **复杂度**: L | **优先级**: P0 | **依赖**: L12.1.1, L12.1.2
- **内容**: 在 validator/v2.rs 中新增 check_deprecations() 函数，遍历原始 JSON Value 树与弃用目录匹配。每个匹配产生 IssueCode::Deprecated 的 ValidationIssue，含具体 JSON 路径、弃用字段、替代建议、严重级别。集成到 validator 主入口。
- **文件**: crates/sb-config/src/validator/v2.rs, crates/sb-config/src/deprecation.rs
- **验收**: WireGuard outbound 配置触发 Deprecated issue；legacy tag 字段触发 warning；5+ 单元测试；现有合法配置零误报

### L12.1.4 — migrate_to_v2() 诊断返回值

- **复杂度**: M | **优先级**: P1 | **依赖**: L12.1.2
- **内容**: compat.rs 的 migrate_to_v2() 当前返回 Value（静默转换）。改为返回 (Value, Vec<MigrationDiagnostic>)，每个 diagnostic 含 from_path、to_path、action（Renamed/Moved/Normalized/Wrapped）、detail。现有转换逻辑不变，仅添加报告。
- **文件**: crates/sb-config/src/compat.rs, app/src/cli/check/run.rs（调用方更新）
- **验收**: V1 配置迁移产生诊断信息；现有测试通过；3+ 单元测试验证具体诊断

### L12.1.5 — Check CLI 弃用输出集成

- **复杂度**: M | **优先级**: P0 | **依赖**: L12.1.3, L12.1.4
- **内容**: 将弃用检测和迁移诊断接入 app check CLI（已有 --migrate/--format/--strict）。标准 check 流程中调用 check_deprecations()；--migrate 显示迁移诊断；--strict 模式下弃用字段导致非零退出码；人类可读格式输出可操作建议。
- **文件**: app/src/cli/check/run.rs
- **验收**: app check 对 WG outbound 配置输出弃用 warning；--migrate --format json 含迁移诊断；--strict 对弃用字段返回非零退出码

### L12.2.1 — WireGuard outbound→endpoint 迁移辅助

- **复杂度**: M | **优先级**: P1 | **依赖**: L12.1.2
- **内容**: 在 compat.rs 新增 migrate_wireguard_outbound_to_endpoint(raw: &Value) -> Option<Value>，将旧 WireGuard outbound 配置转为等效 endpoint 配置（server/port→peer address/port，private_key→endpoint private_key，public_key/pre_shared_key→peer 字段，mtu→endpoint mtu）。
- **文件**: crates/sb-config/src/compat.rs
- **验收**: 转换后 endpoint 配置包含原 outbound 所有字段；3+ 单元测试；可从 app check --migrate 调用

### L12.2.2 — 弃用检测 Interop-Lab 用例

- **复杂度**: M | **优先级**: P1 | **依赖**: L12.1.3
- **内容**: 新增 3 个 interop-lab YAML case 验证弃用检测端到端工作：
  - p1_deprecated_wireguard_outbound.yaml — WG outbound 配置 → 启动日志含弃用 warning
  - p1_deprecated_v1_style_config.yaml — V1 风格配置 → migrate 诊断
  - p1_deprecated_mixed_config.yaml — 混合新旧字段 → 仅弃用字段被标记
- **文件**: labs/interop-lab/cases/ 3 个新 YAML, labs/interop-lab/configs/ 2-3 个测试配置
- **验收**: 3 case 全通过；case list 反映 71+ 总 case

### L12.2.3 — L12 文档与矩阵更新

- **复杂度**: S | **优先级**: P1 | **依赖**: L12.1.3, L12.2.1, L12.2.2
- **内容**: 更新 case_backlog.md、compat_matrix.md、active_context.md 反映 L12 交付。新增"弃用覆盖"一节到 compat_matrix。
- **文件**: labs/interop-lab/docs/case_backlog.md, labs/interop-lab/docs/compat_matrix.md, agents-only/active_context.md
- **验收**: 文档准确反映现状

---

## L13: 服务安全与控制面收敛（8 WP）

### L13.1.1 — Clash API 认证中间件

- **复杂度**: L | **优先级**: P0 | **依赖**: 无
- **内容**: sb-api/src/clash/server.rs 有 auth_token: Option<String> 但从未执行验证。按 Go 实现（clashapi/server.go L256-290）添加 axum 中间件：
  a. token 为空 → 跳过认证
  b. WebSocket 请求 → 检查 ?token= query param
  c. HTTP 请求 → 检查 Authorization: Bearer <token> header
  d. 不匹配 → 401 {"message": "Unauthorized"}
- **文件**: crates/sb-api/src/clash/auth.rs（新建）, crates/sb-api/src/clash/server.rs, crates/sb-api/src/clash/mod.rs
- **验收**: 正确 token → 200；错误 token → 401；无 token+有配置 → 401；WS ?token= 工作；token=None 时全放行；6+ 单元测试

### L13.1.2 — SSMAPI 认证中间件

- **复杂度**: M | **优先级**: P1 | **依赖**: 无
- **内容**: SSMAPI 服务器无任何认证。在 ServiceIR 中新增 ssmapi_auth_token: Option<String>，在 SSMAPI HTTP handler 中实现 Authorization: Bearer 检查。复用 L13.1.1 的模式。
- **文件**: crates/sb-config/src/ir/mod.rs, crates/sb-core/src/services/ssmapi/server.rs, crates/sb-config/src/validator/v2.rs
- **验收**: 有 token 时未认证请求返回 401；token=None 时全放行；3+ 单元测试

### L13.1.3 — 非 localhost 绑定安全警告

- **复杂度**: S | **优先级**: P1 | **依赖**: L12.1.1
- **内容**: 在 validator 中新增检查：当服务（Clash API/SSMAPI/DERP）配置非 localhost 地址（非 127.0.0.1/::1/localhost）且无认证时，发出 IssueCode::Conflict 警告。
- **文件**: crates/sb-config/src/validator/v2.rs
- **验收**: 0.0.0.0:9090 无 secret → 警告；127.0.0.1:9090 → 无警告；0.0.0.0:9090 + secret → 无警告；3+ 测试

### L13.2.1 — 服务故障隔离

- **复杂度**: L | **优先级**: P1 | **依赖**: 无
- **内容**: ServiceManager 在服务启动失败时行为不明确。实现故障隔离：
  a. start_all() 捕获单个服务启动错误并记录日志
  b. 失败服务标记 Failed 状态但不阻止其他服务启动
  c. 新增 ServiceStatus 枚举（Starting/Running/Failed/Stopped）
  d. 聚合健康端点报告每个服务状态
- **文件**: crates/sb-core/src/service.rs, crates/sb-core/src/runtime/runtime_health.rs
- **验收**: 单个服务失败不崩溃主进程；其他服务继续运行；健康端点显示失败服务及错误信息；4+ 单元测试

### L13.2.2 — 服务健康 API 端点

- **复杂度**: M | **优先级**: P2 | **依赖**: L13.2.1
- **内容**: 在 Clash API 中暴露 GET /services/health，返回所有注册服务的聚合健康状态（使用 RuntimeHealth 结构体）。
- **文件**: crates/sb-api/src/clash/handlers.rs, crates/sb-api/src/clash/server.rs
- **验收**: GET /services/health 返回 JSON 含每服务健康状态；2+ 单元测试

### L13.3.1 — 认证执行 Interop-Lab 用例

- **复杂度**: S | **优先级**: P1 | **依赖**: L13.1.1, L13.1.2
- **内容**: 新增 p1_clash_api_auth_enforcement.yaml：配置 secret: "test123"，断言无 token → 401、正确 Bearer → 200、WS ?token= 正确 → 成功、错误 token → 失败。
- **文件**: labs/interop-lab/cases/p1_clash_api_auth_enforcement.yaml（新建）, labs/interop-lab/configs/rust_core_clash_api_auth.json（新建）
- **验收**: case 通过；断言覆盖 401/200 场景

### L13.3.2 — 服务故障隔离 Interop-Lab 用例

- **复杂度**: M | **优先级**: P1 | **依赖**: L13.2.1
- **内容**: 新增 p1_service_failure_isolation.yaml：配置含故意错误的服务（如 SSMAPI 绑定无效地址），验证内核仍启动、Clash API 可达、SOCKS 代理正常、健康端点报告失败服务。
- **文件**: labs/interop-lab/cases/p1_service_failure_isolation.yaml（新建）, labs/interop-lab/configs/rust_core_broken_service.json（新建）
- **验收**: 内核正常启动；核心功能不受影响；健康端点反映失败

### L13.3.3 — L13 验收门禁

- **复杂度**: S | **优先级**: P0 | **依赖**: L13.1.1~L13.3.2
- **内容**: 运行完整 L13 验收：所有新测试通过、所有新 interop-lab case 通过、现有测试不受影响。
- **文件**: agents-only/active_context.md
- **验收**: cargo test --workspace 通过；新 interop-lab case 全通过；active_context 更新

---

## L14: TLS 高级能力与长期质量门禁（10 WP）

### L14.1.1 — 证书存储模式

- **复杂度**: L | **优先级**: P0 | **依赖**: 无
- **内容**: Go 支持三种证书存储模式：system（OS 证书池）、mozilla（内置 Mozilla 根证书）、none（空池）。Rust 当前仅用 webpki-roots（等效 mozilla）。实现：
  a. CertificateStoreMode 枚举（System/Mozilla/None）加入 CertificateIR
  b. sb-tls/src/global.rs 中 base_root_store() 按模式加载证书
  c. System 模式使用 rustls-native-certs crate
  d. 新增 certificate_directory_path 支持（递归加载目录内 PEM 文件）
  e. 字段缺失时默认 System（与 Go 一致）
- **文件**: crates/sb-config/src/ir/mod.rs（CertificateIR ~L2389）, crates/sb-tls/src/global.rs, crates/sb-tls/Cargo.toml（加 rustls-native-certs）, crates/sb-config/src/validator/v2.rs
- **验收**: system 模式加载 OS 证书（macOS 上池非空）；mozilla 模式用 webpki_roots；none 模式空池+仅自定义 CA；目录加载工作；5+ 单元测试

### L14.1.2 — 证书热重载（文件监听）

- **复杂度**: L | **优先级**: P1 | **依赖**: L14.1.1
- **内容**: Go 用 fswatch 监控证书文件变化并自动重载。实现 CertificateWatcher：
  a. 添加 notify crate 依赖
  b. 监控 certificate_path 和 certificate_directory_path
  c. 变化时重载证书并重建 root store
  d. 通过 TLS_OVERRIDE（global.rs 已有机制）更新全局 TLS 配置
  e. CancellationToken 优雅关闭
- **文件**: crates/sb-tls/src/global.rs, crates/sb-tls/Cargo.toml（加 notify）
- **验收**: 配置证书路径时 watcher 启动；修改证书文件触发重载（日志可观测）；新增目录文件触发重载；关闭时 watcher 停止；3+ 单元测试

### L14.1.3 — TLS Fragment 配置→运行时接线验证

- **复杂度**: M | **优先级**: P1 | **依赖**: 无
- **内容**: TLS fragment 运行时已在 sb-core/router/conn.rs 完整实现（tls_fragment/tls_record_fragment/tls_fragment_fallback_delay）。验证从 ConfigIR route 字段到 ConnectionMetadata 的完整链路；确认 validator 识别 tls_fragment 字段；新增 interop-lab case 验证激活。
- **文件**: crates/sb-config/src/validator/v2.rs（验证 allowed keys）, labs/interop-lab/cases/p1_tls_fragment_wiring.yaml（新建）, labs/interop-lab/configs/rust_core_tls_fragment.json（新建）
- **验收**: tls_fragment: true 配置无验证错误；运行时日志显示 fragment 激活；interop-lab case 通过

### L14.1.4 — TLS 能力矩阵验证

- **复杂度**: M | **优先级**: P1 | **依赖**: L14.1.1
- **内容**: 对 Rust 中"已接受限制"的 TLS 特性（uTLS、REALITY、ECH、fragment）添加 validator 信息性诊断。配置引用这些特性时产生 info 级诊断说明当前支持水平；不支持的组合（如 uTLS 非 Chrome 指纹）产生明确错误。
- **文件**: crates/sb-config/src/validator/v2.rs（新增 check_tls_capabilities()）, crates/sb-config/src/deprecation.rs（添加 TLS limitation 条目）
- **验收**: uTLS 配置产生支持指纹的 info 诊断；ECH 配置产生实现状态诊断；4+ 单元测试

### L14.2.1 — Nightly 阈值模板

- **复杂度**: S | **优先级**: P1 | **依赖**: L11.1.2
- **内容**: 基于 L11.1.2 的阈值配置文件，添加命名模板：strict_default（零容错、<5% 退化）、env_limited_default（≤20% 错误率、<10% 退化）、development（宽松）。nightly workflow 按 env_class 选择模板。
- **文件**: labs/interop-lab/configs/trend_thresholds.yaml, .github/workflows/interop-lab-nightly.yml
- **验收**: 三个命名模板存在；nightly 按 env_class 使用对应模板；THRESHOLD_TEMPLATE=strict_default 生效

### L14.2.2 — TLS 综合 Interop-Lab 用例

- **复杂度**: M | **优先级**: P1 | **依赖**: L14.1.1, L14.1.3
- **内容**: 新增 3 个 TLS 相关 interop-lab case：
  - p1_tls_cert_store_mozilla.yaml — mozilla 模式 TLS 连接验证
  - p1_tls_cert_store_none_custom_ca.yaml — none 模式+自定义 CA → self-signed TLS echo 工作
  - p1_tls_fragment_activation.yaml — TLS fragment 激活验证
- **文件**: labs/interop-lab/cases/ 3 个新 YAML
- **验收**: 3 case 全通过；case list 反映 77+ 总 case

### L14.3.1 — L14 集成验证

- **复杂度**: M | **优先级**: P0 | **依赖**: L14.1.1~L14.2.2
- **内容**: 运行 L14 完整集成验证：所有 TLS 测试通过、证书存储模式工作、热重载工作、fragment 接线已验证、所有新 interop-lab case 通过、模板化趋势门禁通过。
- **文件**: agents-only/active_context.md
- **验收**: cargo test --workspace 通过；cargo test -p sb-tls 通过；新 interop-lab case 全通过；active_context 更新

### L14.3.2 — L11-L14 完整 Capstone 验证

- **复杂度**: S | **优先级**: P0 | **依赖**: L11.1.4, L12.2.3, L13.3.3, L14.3.1
- **内容**: 最终验证：cargo test --workspace 通过（1500+ tests）、全部 strict interop-lab case 通过、趋势门禁 P0 通过、边界检查通过。更新 CLAUDE.md 和 active_context.md。
- **文件**: CLAUDE.md, agents-only/active_context.md
- **验收**: workspace 测试通过；make boundaries exit 0；所有 strict case 通过；P0 趋势门禁通过

---

## 批次调度

### Batch 1（无依赖，8 项，全并行）

| ID | 标题 | 复杂度 | 类型 |
|---|---|---|---|
| L11.1.1 | 规划文档过期文本修正 | S | 文档 |
| L11.1.2 | 趋势门禁阈值模板配置化 | M | 脚本+YAML |
| L12.1.1 | IssueCode::Deprecated 枚举 | S | Rust |
| L12.1.2 | 集中化弃用目录模块 | M | Rust 新模块 |
| L13.1.1 | Clash API 认证中间件 | L | Rust+测试 |
| L13.1.2 | SSMAPI 认证中间件 | M | Rust |
| L13.2.1 | 服务故障隔离 | L | Rust+测试 |
| L14.1.1 | 证书存储模式 | L | Rust+测试 |

### Batch 2（依赖 Batch 1，8 项）

| ID | 标题 | 依赖 | 复杂度 |
|---|---|---|---|
| L11.1.3 | 历史趋势追踪 | L11.1.2 | M |
| L11.1.4 | L11 验收门禁 | L11.1.1, L11.1.2 | S |
| L12.1.3 | 验证器弃用检测 Pass | L12.1.1, L12.1.2 | L |
| L12.1.4 | migrate_to_v2() 诊断返回 | L12.1.2 | M |
| L12.2.1 | WireGuard 迁移辅助 | L12.1.2 | M |
| L13.1.3 | 非 localhost 绑定警告 | L12.1.1 | S |
| L14.1.2 | 证书热重载 | L14.1.1 | L |
| L14.1.3 | TLS fragment 接线验证 | 无 | M |

### Batch 3（依赖 Batch 2，7 项）

| ID | 标题 | 依赖 | 复杂度 |
|---|---|---|---|
| L12.1.5 | Check CLI 弃用输出集成 | L12.1.3, L12.1.4 | M |
| L12.2.2 | 弃用检测 interop-lab 用例 | L12.1.3 | M |
| L13.3.1 | 认证执行 interop-lab 用例 | L13.1.1, L13.1.2 | S |
| L13.3.2 | 服务故障隔离 interop-lab 用例 | L13.2.1 | M |
| L13.2.2 | 服务健康 API 端点 | L13.2.1 | M |
| L14.1.4 | TLS 能力矩阵验证 | L14.1.1 | M |
| L14.2.1 | Nightly 阈值模板 | L11.1.2 | S |

### Batch 4（依赖 Batch 3，4 项）

| ID | 标题 | 依赖 | 复杂度 |
|---|---|---|---|
| L12.2.3 | L12 文档与矩阵更新 | L12.1.3, L12.2.1, L12.2.2 | S |
| L13.3.3 | L13 验收门禁 | L13.1.1~L13.3.2 | S |
| L14.2.2 | TLS 综合 interop-lab 用例 | L14.1.1, L14.1.3 | M |
| L14.3.1 | L14 集成验证 | L14.* all | M |

### Batch 5（Capstone，1 项）

| ID | 标题 | 依赖 | 复杂度 |
|---|---|---|---|
| L14.3.2 | L11-L14 完整 Capstone | L11.1.4, L12.2.3, L13.3.3, L14.3.1 | S |

---

## 依赖图

- **Batch 1** (Parallel): L11.1.1, L11.1.2, L12.1.1, L12.1.2, L13.1.1, L13.1.2, L13.2.1, L14.1.1
- **Batch 2**: Depends on Batch 1
- **Batch 3**: Depends on Batch 2
- **Batch 4**: Depends on Batch 3
- **Batch 5**: Final Capstone

---

## 验证策略

1. **单 WP 单元测试**: 每个产出 Rust 代码的 WP 必须有单元测试。目标: 40+ 新测试
2. **Interop-lab 用例**: 每个功能性 WP 至少产出一个 case。目标: 9+ 新 YAML case（总计 77+）
3. **回归门禁**: 每个 Batch 完成后运行 cargo test --workspace + make boundaries
4. **Schema 兼容性**: CaseSpec/IR 变更必须通过 case list 和 cargo check --workspace
5. **CI workflow 验证**: L11 闭环后 nightly workflow 必须成功运行
6. **Go parity 对照**: 认证中间件行为必须与 Go 实现完全一致（相同 HTTP 状态码、相同 token 提取逻辑）
7. **文档同步**: 每个 Batch 后更新 case_backlog.md、compat_matrix.md、active_context.md

---

## 风险登记

| 风险 | 可能性 | 影响 | 缓解 |
|---|---|---|---|
| rustls-native-certs 在 CI Linux 上兼容性问题 | 中 | 高 | macOS/Linux 双平台测试；系统证书不可用时回退 mozilla 模式 |
| 认证中间件破坏 auth_token=None 的现有测试 | 低 | 中 | 中间件在 token=None 时跳过认证（完全匹配 Go 行为） |
| notify 文件监听器在 CI 中不工作（无真实文件变化） | 中 | 低 | 单元测试 mock 文件变化；真实 watcher 仅在集成测试中验证 |
| 弃用目录过时（新字段未添加） | 低 | 中 | 单元测试验证目录覆盖所有已知弃用模式 |
| CertificateIR 变更破坏现有配置解析 | 中 | 高 | 所有新字段为 Option + #[serde(default)]；向后兼容 |
| 服务故障隔离引入微妙行为变化 | 中 | 中 | 仅隔离明确启动失败的服务；运行中服务行为不变 |

---

## 统计摘要

| 指标 | 值 |
|---|---|
| 总工作包 | 30 |
| 批次 | 5 |
| L11 WP | 4（闭环） |
| L12 WP | 8（迁移治理） |
| L13 WP | 8（服务安全） |
| L14 WP | 10（TLS+质量） |
| 预计新 Rust 源文件 | 3（deprecation.rs, auth.rs, cert watcher） |
| 预计新 interop-lab case | 9 |
| 预计新单元测试 | 40+ |
| 复杂度分布 | S:10, M:13, L:7 |
| 优先级分布 | P0:8, P1:18, P2:4 |

## 关键实现文件

| 文件 | 涉及 WP | 说明 |
|---|---|---|
| crates/sb-types/src/lib.rs | L12.1.1 | IssueCode::Deprecated 基础 |
| crates/sb-config/src/deprecation.rs | L12.1.2, L12.1.3, L14.1.4 | 弃用目录+检测（新建） |
| crates/sb-config/src/compat.rs | L12.1.4, L12.2.1 | 迁移诊断+WG 迁移 |
| crates/sb-config/src/validator/v2.rs | L12.1.3, L12.1.5, L13.1.3, L14.1.4 | 弃用检测/安全警告/TLS 验证 |
| crates/sb-api/src/clash/auth.rs | L13.1.1 | Clash API 认证中间件（新建） |
| crates/sb-api/src/clash/server.rs | L13.1.1, L13.2.2 | 中间件集成+健康端点 |
| crates/sb-core/src/service.rs | L13.2.1 | 服务故障隔离 |
| crates/sb-tls/src/global.rs | L14.1.1, L14.1.2 | 证书存储模式+热重载 |
| app/src/cli/check/run.rs | L12.1.5 | CLI 弃用输出 |
