<!-- tier: C -->
# AI Activity Log（AI 行为日志）

> 🚫 **AGENT 勿主动读取**：C-tier 审计留痕（~479KB），不参与上下文推断。
> 仅在明确需要回溯某次具体历史动作时按需 `grep`。
> ✍️ 写入仍照旧：每个 AI 在完成任务前自动追加一行日志条目。
> **C-tier**：持续写入，但不主动读取。需要审计时通过 git log 或 grep 检索。

---

## 日志格式
### [YYYY-MM-DD HH:MM] Agent: [Agent Name/ID]

**任务**: [描述具体任务]
**变更**:
- [文件路径] - [具体变更内容]
**结果**: [成功/失败 + 输出摘要]
**备注**: [可选，风险/后续建议]


> 📦 2026-03-26 之前的旧日志已滚动归档至 `archive/logs/log_rollup_2026H1.md`(2026-07-07)。
> 本文件超过 10000 行时,重复该滚动:旧段 git mv/append 进 archive/logs/,保留头部+最近条目。

## 2026-03-26 sb-config outbound.rs Raw/Validated 边界试点

**任务**: 为 `crates/sb-config/src/outbound.rs` 建立 Raw → Validated 配置边界试点

**完成内容**:
- 将 `outbound.rs` 转换为 `outbound/mod.rs` + `outbound/raw.rs` 模块结构
- `raw.rs`: 16 个 Raw 类型全部 `#[serde(deny_unknown_fields)]`，承接所有 serde 反序列化
- `mod.rs`: 16 个 domain 类型不再 `derive(Deserialize)`，通过自定义 `impl Deserialize` 走 Raw 中转
- 16 组 `From<Raw*> for *` 无损转换
- 新增 27 个定点测试（`outbound_raw_boundary_test.rs`）

**未触碰**:
- `ir/mod.rs` — 仍是结构 blocker
- `validator/v2.rs` — 仍是结构 blocker
- sb-config 整体仍在第一波 blocker 列表中

**验证**: cargo check/test/clippy 全 pass，inbound-errors.sh pass

---

## 2026-06-27 P1313-06 Adapter Surface Contracts

**任务**: 实现 post1313 任务包 06，暴露 Rust adapter-facing surface contracts。

**完成内容**:
- `sb-types::ports` 新增对象安全的 adapter contract surface 与 `BoxFuture` 端口模式。
- `sb-core::adapter::surface` 将 `ContextRegistry` 中的 CacheFile、URLTest history、
  Clash、V2Ray、time、certificate 等服务桥接为 `sb_types::ports::*` trait objects。
- `AdapterInboundContext` / `AdapterOutboundContext` 新增 `services()`。
- `CacheFile` context trait 增加 FakeIP、RDRC、rule-set hooks；`CacheFileService`
  接入已有存储行为。
- 新增跨 crate contract test，验证消费方无需 concrete downcast。

**验证**:
- `cargo check -p sb-types`
- `cargo check -p sb-core --features router`
- `cargo check -p sb-adapters`
- `cargo check -p app --features parity`
- `cargo check --workspace --all-features`
- `cargo test -p sb-types`
- `cargo test -p sb-core adapter_services_expose_trait_object_contracts_without_downcast --features router`
- `./agents-only/06-scripts/verify-consistency.sh`
- `make boundaries`
- `cargo fmt --check`

**结果**: P1313-06 DONE。未声明 dual-kernel parity 变化；router 直连派发仍留作后续 wiring。

---

## 2026-06-27 P1313-07 CacheFile Persistence

**任务**: 实现 post1313 任务包 07，让 Rust CacheFile 成为真实持久化服务。

**完成内容**:
- 保留 Rust sled 后端，不实现 Go bbolt `cache.db` 文件级兼容；普通文件路径显式报错。
- `CacheFileService::try_new` 成为生产构造入口；无路径默认 `cache.db`，腐败 sled 目录移动到
  `.corrupt.<timestamp>` 后重建，不再静默退回内存。
- Clash mode、selector selected/group expansion、RDRC、rule-set payload 按 `cache_id`
  隔离；FakeIP 保持全局，并拆分 IPv4/IPv6 domain 映射。
- RDRC 按 transport/qtype/qname 保存拒绝状态并在过期读取时删除；`store_rdrc=false`
  完全不读写。
- Rule-set CacheFile payload 升级为 typed v2，并兼容读取旧 Rust raw `rulesets` tree。
- app/supervisor/API/DNS/FakeIP/rule-set 路径接入共享 CacheFile，启动/reload 传播初始化错误。

**验证**:
- `cargo test -p sb-core cache_file`
- `cargo test -p sb-core dns`
- `cargo test -p sb-core --test supervisor_reload_state`
- `cargo test -p sb-core --test adapter_surface_contract`
- `cargo test -p sb-api clash`
- `cargo test -p sb-core --test router_ruleset_integration test_remote_ruleset_cachefile_fallback_preserves_metadata`
- `cargo check -p sb-core --features router`
- `cargo check --workspace --all-features`
- `./agents-only/06-scripts/verify-consistency.sh`
- `make boundaries`
- `cargo fmt --check`

**结果**: P1313-07 DONE。未添加 GitHub Actions，未声明 dual-kernel parity 变化。

---

## 2026-06-30 app release hygiene

**任务**: 执行 `app/` release-level cleanup：移除死代码、纯占位/永禁测试、假补丁 builder 和 stale 本地 artifact。

**完成内容**:
- 删除未接入的 `app/src/run_go.rs`、`app/src/cli/probe.rs`、空 tracked 测试、永禁 legacy E2E、纯占位 TLS/TUIC/UDP/TUN 测试，以及模拟式 multihop/performance validation 噪声。
- `app` analyze registry 改为调用真实 `sb_core::router::analyze_fix` patch builder；`supported_patch_kinds()` 同时支持当前 `patch_kinds` 与历史 `kinds` payload。
- `merge` bin 在 `app/Cargo.toml` 显式声明；误导性的 `bootstrap`/战略大段注释压缩为当前 `run_engine` 口径。
- 修正删测后的脚本/feature scanner stale 引用；清理 ignored `app/target/rc` 残留。

**验证**:
- `cargo test -p app --all-features --test registry_demo`
- `cargo test -p app --all-features supported_patch_kinds_parse_current_core_payload`
- `cargo check -p app --all-targets --all-features`
- `cargo test -p app --all-features --test performance_validation`
- `cargo test -p app --all-features --test protocol_integration_validation_test`
- `cargo test -p app --all-features --test protocol_chain_e2e test_http_to_direct_chain`
- `cargo test -p app --all-features --test shadowsocks_validation_suite test_ss_tcp_connectivity_foundation`
- `cargo fmt --check`
- `git diff --check`

**结果**: `app/` hygiene DONE locally。未添加 GitHub Actions，未声明 REALITY/dual-kernel parity 变化。

---

## 2026-07-07 agents-only 高强度压缩 + 记忆系统自动维护升级

**任务**: 压缩 agents-only 陈旧文档、降低 agent 启动记忆负担、升级自动维护流程
**变更**:
- git mv 封箱 MT-REAL-02 文档(baseline/3 intakes/a41/a42/mt_mixed_fresh_evidence)→ archive/mt_real_02/;workflow_notes.md → memory/
- active_context.md 299→~126 行(15 个 2026-07-03 audit-cleanup 段压成一条合并摘要)
- log.md 旧段(20-8494 行)滚动归档 → archive/logs/log_rollup_2026H1.md
- CLAUDE.md 反漂移修正(目录树改指针、MT-GUI/MT-AUDIT 失效路径改 mt_summary.md、边界门禁易变数字改指针)
- verify-consistency.sh 新增:S-tier 行数上限(hard)、顶层白名单(hard)、Resume 陈旧度/log 超长/tier 标记(advisory)
- 全 repo 引用路径修复(含 trojan.rs 注释、golden_spec、AGENTS.md);未移动:mt_real_01/02_evidence(scripts/tools 硬编码)、fable5审计报告(2026-06-29 处置决定)
**结果**: 成功;verify-consistency.sh exit 0;断链扫描零残留;cargo check -p sb-adapters PASS
**备注**: 顶层白名单今后由 verify-consistency.sh 强制;新轨迹目录需登记 README + 脚本 ALLOWED_DIRS
