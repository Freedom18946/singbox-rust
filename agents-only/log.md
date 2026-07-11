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

---

## 2026-07-10 MIG-03 WP01 Trait Census + Canonical Contract ADR

**任务**: 完成 MIG-03 WP01（Trait 契约全量盘点与正典契约 ADR）。

**变更**:
- 新增 `mig03_wp01_trait_census.md`：覆盖 outbound/inbound/UDP 主证据与补充接口，记录实现/调用证据、对象安全、UDP 能力差异和移交项。
- 新增 `mig03_adr01_canonical_connector.md`：依 D1-D8 固化 `sb-types` 正典 outbound/inbound/packet 契约、错误映射、Session options、迁移删除表和 Go 对照。
- 更新 WP01 包状态/验收清单与 `active_context.md`；不改生产代码。

**验证**:
- WP01 文档完整性检查（19 个相关 trait 定义、D1-D8、迁移表、无未决项）
- `git diff --check`
- `cargo check -p sb-core --quiet`
- 复现并记录 `adapter-trojan,router` 独立 feature gate 失败（留给后续包，未在本包修复）

**结果**: WP01 DONE。未声明 dual-kernel parity / BHV / REALITY 变化。

---

## 2026-07-10 MIG-03 WP01-03 red-team acceptance + canonical cutover

**任务**: 验收 WP01/WP02/WP03；补齐所有发现缺口并关闭 combined cutover。

**变更**:
- 修正 WP01 census/ADR 漏项与错误基线计数；删除遗漏死 factory。
- 正典 outbound/inbound/PacketConn 全面落位；删 legacy traits、handler aliases、
  manager compatibility spellings、`connect_io`、`sb-proto`。
- register wrapper 清零；PacketConn finalized Session、deadline、idle timeout、close、
  capability 声明一致；named stream routing 统一 canonical boxed dial。
- 边界 V8 加递归 wrapper scan 与 registration aggregate LOC 报告；同步 SPECS、
  structure、active context、WP 状态。

**验证**:
- global five gates；sb-types/sb-adapters/sb-core tests；PacketConn focused tests；
  scaffold smoke；Trojan isolated feature；DERP no-default feature check。
- dual-kernel `p1_rust_core_tcp_via_socks`、`p1_rust_core_udp_via_socks` run+diff clean。

**结果**: WP01/WP02/WP03 DONE。Parity/BHV、packaging、REALITY 状态不变。

---

## 2026-07-11 MIG-03 WP04 scaffold semantic audit

**任务**: 完成 WP04 scaffold/adapters 逐协议语义审计与 WP05/WP06 唯一施工单。

**变更**:
- 新增 `mig03/mig03_wp04_coverage_matrix.md`：纠正“主 bridge 普遍 fallback”过期假设，
  覆盖主 bridge、legacy `Bridge::new_from_config`、switchboard 三条构造路径。
- 对每个相关协议完成配置、认证、TCP、UDP、错误、metrics、`SB_*`、sniff/route
  八维审计；登记 D9/D10/D14 裁决、交叉依赖、测试处置及 Go parity 发现。
- 确认 WP05 只有两组 GAP：SOCKS inbound（limiter、active TCP、兼容 metrics、core UDP
  依赖）与 SOCKS outbound（产品 profile UDP、core helper）；selector/urltest 去重仍归
  WP12；无 D18 未决项。
- 更新 WP04 状态、验收清单和 active context；未修改生产代码或测试。

**验证**:
- 矩阵结构/八维完整性检查
- 矩阵锚点与 grep 证据复现
- `git diff --check`
- `./agents-only/06-scripts/verify-consistency.sh`
- `make boundaries`
- `cargo fmt --check`
- `cargo check -p app`

**结果**: WP04 DONE。未声明 dual-kernel parity / BHV / REALITY / packaging 变化。

---

## 2026-07-11 MIG-03 WP05 adapters gap closure

**任务**: 彻底实现并验收 WP05，关闭 WP04 矩阵两组 SOCKS GAP。

**变更**:
- SOCKS/mixed adapter接入既有 per-IP limiter；SOCKS driver实现 active TCP与兼容
  associate/packet/active metrics。
- `UdpUpstreamMap`/`UpSocksSession`/active proxy transport迁入 sb-adapters，复用 canonical
  PacketConn并保持 D14 env、timeout alias、wire-size、错误与观测语义。
- 产品 feature闭合 SOCKS UDP；core scaffold tests迁为 adapter/app active E2E，保留 WP12
  generic balancer边界。
- 修复 probe canonical-dial重构后的陈旧 Python源码锚点；更新 WP04 matrix、WP05包、
  active context。

**验证**:
- sb-adapters default/all-features、sb-core regression、app acceptance/gui_runtime/parity、
  isolated SOCKS/router feature全部通过。
- workspace check/clippy、fmt、boundaries、diff-check、Python三套工具回归全部通过。
- SOCKS TCP/UDP与mixed双核run两侧traffic success，errors为空。

**结果**: WP05 DONE；实现提交 `de25101d`。无 D18、无 parity/BHV/REALITY/packaging
移动；WP06已解锁，WP12边界未动。

---

## 2026-07-11 MIG-03 WP06 scaffold retirement

**任务**: 完整移除 bridge scaffold fallback、core 重复协议实现与 scaffold feature。

**变更**:
- bridge/legacy constructor/runtime switchboard 全部改为 canonical adapter registry；未命中或
  配置拒绝成为含 tag/kind 的 fatal startup error，阻止 READY。
- `OutboundImpl` 收敛为单一 Connector；direct/block 唯一归属 adapters；inbound TCP helper
  迁入 adapters 并保留 DNS、keepalive、handshake、telemetry 语义。
- 删除 16 个 core legacy 文件和 scaffold Cargo 面；净删 5818 行。boundary V8 新增硬断言。
- 重写 registry fatal/no-READY 测试；显式化 SS/Trojan 测试路由；修复 interop TLS fixture、
  rustls provider 与 Trojan upstream 诊断。

**验证**:
- sb-core/sb-adapters/app 全套测试；workspace all-target/all-feature check；strict clippy；fmt；
  boundaries 493 assertions；diff-check 全绿。
- SS/Trojan net-e2e、registry 2/2、release GUI mixed→direct curl 全绿。
- final strict interop 87/95；WP06 触及 case 全绿。剩余既有 harness/config/S4 基线逐项记录
  于 WP06；env-limited 7/8。未新增 dual-kernel 差分。
- gui_runtime binary 40,764,944 → 40,522,992 bytes（-241,952，-0.59%）。

**结果**: WP06 DONE；WP07 解锁。无 parity/BHV/REALITY/packaging denominator 移动。

---

## 2026-07-11 MIG-03 WP08 router stack merge

**任务**: 合并 `router/` + `routing/`，统一 Engine、matcher、explain/trace 与热加载路径。

**变更**:
- ConfigIR engine/explain/trace 迁入 router；routing 收敛为 23 行 WP14 兼容 facade，删除
  duplicate IR/matcher/router 实现；legacy bucket evaluator 更名 `RuleEngine`。
- 消费方全切 `router::{Engine, Input, ExplainEngine}`；suffix 原语统一给 ConfigIR 与
  RuleMatcher，DNS 继续复用 RuleMatcher；explain JSON 新增精确序列化锁。
- rule-hot-reload 改用 canonical RouterHandle/RouterIndex 原子替换与正典配置流水线，新增
  external rules 决策测试；同步 boundary 文件搬迁断言。
- 闭合验收暴露的旧漂移：tools profile SSH 测试假设、ShadowTLS runtime registry 发布、
  TUIC v5 password credential、FakeIP strict type fixture。

**验证**:
- global five gates；sb-core full/router/dns/hot-reload；app `router,tools` full；专项
  router_options/tun_sni/explain；Python tools 232 PASS。
- dual-kernel route/DNS 五 case 均 gate_score=0、zero mismatch。

**结果**: WP08 DONE；routing 7 files/1487 LOC → 1 file/25 LOC；WP11 解锁。无新增
parity/BHV/REALITY/packaging movement。
