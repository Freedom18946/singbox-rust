<!-- tier: S -->
# 工作阶段总览（Workpackage Map）

> **用途**：阶段划分 + 当前位置。S-tier，每次会话必读。
> **纪律**：Phase 关闭后压缩为一行状态。本文件严格 ≤120 行。
> **对比**：本文件管“在哪”；`active_context.md` 管“刚做了什么 / 下一步”。

---

## 已关闭阶段（一行总结）

| 阶段 | 交付 | 关闭时间 |
|------|------|----------|
| L1-L17 | 架构整固、功能对齐、CI / 发布收口 | 2026-01 ~ 2026-02 |
| MIG-02 / L21 | 隐式回退消除，541 V7 assertions，生产路径零隐式直连回退 | 2026-03-07 |
| L18 Phase 1-4 | 认证替换、证据模型收口、GUI gate 复验、长跑恢复决策门 | 2026-03-11（历史阶段） |

## 当前阶段：L22 dual-kernel parity 收口

工作包 ID：`WP-L22`

- 目标：只用诚实的 Go/Rust strict both-case 提高 `Both-Covered`
- SoT：`labs/interop-lab/docs/dual_kernel_golden_spec.md`
- 当前口径：
  - 不把 Rust-only 单测记成 parity 完成
  - 不把 repo-level 自动化 / soak / nightly 记成 behavior 覆盖完成
  - 不做 coverage-neutral 的 promote 充当新增 BHV 覆盖

## 当前分数（2026-03-15）

| 指标 | 当前值 |
|------|--------|
| `Both-Covered` | `50 / 60` |
| 覆盖率 | `83.3%` |
| strict both 覆盖 | `42 / 60` |
| both-case ratio | `35 / 95` |

## 本轮已真实新增的 both 覆盖

| Case | 行为 / 收益 | 备注 |
|------|-------------|------|
| `p1_gui_connections_tracking` | `BHV-DP-010` + `BHV-CP-006` | 在 live SOCKS 请求未结束时抓 `/connections` |
| `p1_gui_ws_reconnect_behavior` | `BHV-LC-008` | restart 期间 `/connections` WS 关闭且 ready 后可重连 |
| `p1_selector_switch_traffic_replay` | `BHV-LC-006` | selector 选中态在 reload 后保持 |
| `p1_lifecycle_restart_reload_replay` | `BHV-LC-009` | shutdown 后同端口 restart 恢复 |
| `p1_fakeip_dns_query_contract` | `BHV-DP-016` | 双核 `/dns/query` fakeip contract |
| `p1_fakeip_cache_flush_contract` | `BHV-DP-017` | 双核 fakeip flush/reset contract |
| `p0_clash_api_contract_strict` | `BHV-PF-002` | repeated `GET /proxies` p95 latency contract |
| `p1_rust_core_http_via_socks` | `BHV-PF-001` | repeated HTTP via SOCKS5 p95 latency contract |
| `p1_dns_cache_ttl_via_socks` | `BHV-DP-018` | TTL 内缓存命中、TTL 后重新查询 |
| `p1_domain_rule_via_socks` | `BHV-DP-012` | 域名规则精确匹配 FQDN（修复 direct_connect IPv6-first bug） |
| `p2_connections_ws_soak_dual_core` | `BHV-PF-004` | Spec 修正：leak_detected 断言覆盖线性内存增长检测 |
| `p1_mixed_inbound_dual_protocol` | `BHV-DP-004` | 修复 mixed inbound peek→read_exact bug，SOCKS5+HTTP CONNECT 同端口检测 |
| `p1_graceful_shutdown_drain` | `BHV-LC-007` | 新 TcpDrainDuringShutdown harness 原语，双核 SIGTERM 行为一致性验证 |
| `p1_urltest_auto_select_replay` | `BHV-DP-007` | 修复 now() + 初始健康检查，URLTest 自动选择最低延迟出站 |

## 本轮顺带补齐的产品 / harness 能力

1. Rust Clash API `dns_resolver` 接线到运行时，`GET /dns/query` 不再天然 `503`
2. Rust fakeip flush 接到 core fakeip state，而不是静态 stub
4. Rust URLTest `now()` 修复为调用 `select_by_latency()` + 初始健康检查立即执行
   - `command_start` / `command_wait` / `api_http`
   - per-kernel `api_http` method/path/status override
   - `eq_ref` / `ne_ref` 断言

## 当前优先级

1. `p1_service_failure_isolation`
   - 确认不可行：Go 结构性 fail-fast，所有 service init 错误均 fatal abort
   - Go `box.start()` → `adapter.Start()` → `service.Manager.Start()` → 首个错误立即返回
   - 不可与 Rust 的 best-effort 隔离模型统一
2. L22 实质性天花板：83.3%
   - 剩余 10 个未覆盖 BHV：7 SV 结构性阻塞 + 2 KNOWN-GAP + 1 已确认不可行
   - 无结构性产品变更时，不可能再提高覆盖率

## 明确不再重复的方向

- `/connections` dual-core soak / trend gate / nightly 已有，不再当新增覆盖
- `api_ws_soak` traffic action 已有，不再重复补
- `p1_gui_connections_tracking` 已完成，不再回头做 active entry 可见性
- `BHV-DP-012` domain-rule both-case 当前更像真实行为缺口，不要硬记
- mixed inbound peek→read_exact bug 已修复，BHV-DP-004 已覆盖
- `p1_urltest_auto_select_replay` 已完成，now() 修复已落地
- `p1_service_failure_isolation` 已确认不可行，不再尝试

## 每次新增 both-case 的最小流程

1. 检查 case YAML、Go/Rust config、oracle ignore / tolerance 是否缺失
2. 实跑：
   - `cargo run -p interop-lab -- case run ... --kernel both --env-class strict`
   - `cargo run -p interop-lab -- case diff ...`
3. 更新：
   - `labs/interop-lab/docs/dual_kernel_golden_spec.md`
   - `labs/interop-lab/docs/compat_matrix.md`
   - `labs/interop-lab/docs/case_backlog.md`（必要时）
   - `AGENTS.md`
   - `agents-only/active_context.md`

## 当前入口

- 当前工作包：`agents-only/planning/L22-DUAL-KERNEL-PARITY.md`
- 当前状态快照：`agents-only/active_context.md`
- parity 执行规则：`AGENTS.md`
