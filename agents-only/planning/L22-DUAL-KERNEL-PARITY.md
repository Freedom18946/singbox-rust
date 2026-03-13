<!-- tier: A -->
# L22 工作包：Dual-Kernel Parity 收口

状态：🔄 进行中
更新：2026-03-14

> **定位**：
> 当前阶段只服务于一个目标：提高 `labs/interop-lab/docs/dual_kernel_golden_spec.md` 的 `Both-Covered`，并且只承认诚实的 strict both-case 证据。

---

## 1. 当前目标

1. 继续增加 Go / Rust 双核共同覆盖的行为数。
2. 优先把已有 strict replay / contract / routing case 提升成 `kernel_mode: both`。
3. 仅在目标 case 被真实产品缺口阻塞时，补最小必要产品修复或 harness 能力。

## 2. 当前分数

- `Both-Covered = 39 / 60`
- 覆盖率 `65.0%`
- strict both 覆盖 `31 / 60`
- both-case ratio `29 / 94`

## 3. 本轮已完成的新增覆盖

1. `p1_gui_connections_tracking`
   - 诚实覆盖：`BHV-DP-010`、`BHV-CP-006`
   - 核心点：在 live SOCKS 请求未结束时抓 `/connections`
2. `p1_lifecycle_restart_reload_replay`
   - 诚实覆盖：`BHV-LC-001`
   - 核心点：reload 改走真实 `SIGHUP` fallback
3. `p1_fakeip_dns_query_contract`
   - 诚实覆盖：`BHV-DP-016`
   - 核心点：双核 `/dns/query` fakeip 返回 contract
4. `p1_fakeip_cache_flush_contract`
   - 诚实覆盖：`BHV-DP-017`
   - 核心点：Rust / Go 分别走真实 fakeip flush 语义后验证 reset

## 4. 本轮新增能力

### 4.1 产品侧

- Rust Clash API `dns_resolver` 接线到运行时，`GET /dns/query` 不再天然 `503`
- Rust fakeip flush 接线到 core fakeip state

### 4.2 interop-lab 侧

- `command_start`
- `command_wait`
- `api_http`
- per-kernel `api_http` method/path/status override
- `eq_ref`
- `ne_ref`

## 5. 当前 blocker

1. `p1_service_failure_isolation`
   - Rust `/services/health` 还是 static stub
   - 尚无真实 broken-service dual-core model
2. `BHV-DP-012`
   - domain-rule both-case 之前试验更像真实行为缺口
3. mixed inbound
   - 仍有真实 Rust gap
4. `p1_urltest_auto_select_replay`
   - Rust vs Go auto-selection 语义分歧仍未对齐

## 6. 下一步顺序

1. 先评估 `p1_service_failure_isolation` 是否能被改造成真实 broken-service dual-core model
2. 若不能诚实拿 `BHV-LC-003`，则跳过，不做假覆盖
3. 继续寻找可以快速新增 `Both-Covered` 的 strict both routing / lifecycle / service case

## 7. 执行纪律

1. 先检查 case YAML、Go/Rust config、oracle ignore / tolerance 是否缺失
2. 每完成一个 both-case，必须实际运行：
   - `cargo run -p interop-lab -- case run ... --kernel both --env-class strict`
   - `cargo run -p interop-lab -- case diff ...`
3. 每完成一个 both-case，必须同步：
   - `labs/interop-lab/docs/dual_kernel_golden_spec.md`
   - `labs/interop-lab/docs/compat_matrix.md`
   - `labs/interop-lab/docs/case_backlog.md`（必要时）
   - `AGENTS.md`
   - `agents-only/active_context.md`
4. 不回滚工作区里的非本任务改动
5. 不把 artifacts / soak / nightly 当成 behavior 覆盖本身
