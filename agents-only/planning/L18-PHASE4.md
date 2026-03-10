<!-- tier: A -->
# L18 Phase 4 工作包：全局静态审议整改

状态：🔄 进行中
更新：2026-03-11

> **定位**：
> 当前会话不再充当 `nightly/certify` 盯跑入口。
> Phase 4 的唯一目标是把全局静态审议意见落成可信问题清单、整改顺序和恢复长跑的决策门。

---

## 1. 总体顺序

执行顺序固定为三波：

1. **Wave A: 证据模型收口**
2. **Wave B: 边界 / 脚手架 containment**
3. **Wave C: 长跑恢复决策门**

在 Wave A/B 完成前，不直接恢复 `nightly` 或 `certify`。

## 1.1 当前执行位置（2026-03-11）

已确认事实：

1. `daily-core` 已稳定可跑。
2. `host-gui` 的 GUI gate 已拿到独立 `PROVEN` 证据。
3. 原先卡住长链路的 `workspace_test -> bench_outputs_json` 已在本地 harness 层修稳。
4. 后续暴露出的 `interop-lab` `TrojanInboundConfig.reality` 初始化器漂移已修正，`cargo test -p interop-lab --no-run` 已通过。
5. 后续暴露出的 `shadowtls_e2e` / `shadowtls_inbound_e2e` rustls process-level `CryptoProvider` 初始化缺口已修正，窄测已通过。
6. 最新 fixed-profile batch `20260310T214322Z-l18-daily-preflight` 已重跑到 `workspace_test` 中后段，前述新失败点未再复现；在该 batch 完整结束并刷新 manifest 前，不恢复 `nightly/certify`。

因此当前顺序固定为：

1. 等当前 `daily-host-gui` / fixed-profile 完整结束，确认 `workspace_test` 新旧失败点均已收口
2. 使 `daily-host-gui` 重新变成完整可复跑 batch
3. 再进入协议 parity 收口：
   - `trojan`
   - `shadowsocks`
   - `shadowtls`（后置）

## 2. Wave A：证据模型收口

目标：切断 docs-only 口径对 `209/209`、`100% parity`、`release-ready` 之类强结论的自证。

执行项：

1. 将 `reports/capabilities.json` 升到 `schema_version=1.1.0`。
2. 拆分 `capabilities[]` 与 `acceptance_closure`：
   - `capabilities[]` 只表达产品能力。
   - `acceptance_closure` 单独表达 closure narrative 的证据状态。
3. `claims[]` 新增：
   - `claim_kind = capability | closure | historical`
   - `linked_ids[]`
4. `scripts/check_claims.sh` 改为硬阻断：
   - 活跃入口出现 closure 话术时，若 `acceptance_closure.status != evidence_backed`，直接失败。
5. L18 保留批次必须输出 `evidence_manifest.json`：
   - `batch_id`
   - `profile`
   - `commit`
   - `command`
   - `artifact_hashes`
   - `gate_summary`
   - `port_map`

## 3. Wave B：边界 / 脚手架 containment

目标：把当前主路径固定到单一入口，并限制新的 bridge / global registry 污染继续扩散。

执行项：

1. 运行入口固定为：
   - `app::run_engine::run_supervisor`
2. `app/src/bootstrap.rs` 视为 legacy/dead path：
   - 不再作为活跃入口文档描述。
3. 新增显式 registry 构造与启动路径：
   - `build_default_registry()`
   - `Supervisor::start_with_registry(...)`
4. `run_engine` 切到显式 registry。
5. `sb_adapters::register_all()` 仅留给 tests / legacy compatibility。
6. 边界治理改为版本化 policy：
   - `V4a <= 23`
   - `V4b` informational
   - 不得新增 `AdapterIoBridge` 实例点
   - 不得新增产品路径 `bridge.inbounds` 启动
   - 不得新增产品路径全局注册调用

## 4. Wave B：L18 harness 语义与资源卫生

目标：让 `PASS` 不再掩盖 `WARN` / `optional-unavailable` / 固定端口泄漏这类结构问题。

执行项：

1. `l18_capstone_status.json` / `gui_real_cert.json` 状态词统一为：
   - `PROVEN`
   - `PARTIAL`
   - `ADVISORY`
   - `UNTESTED`
   - `FAILED`
2. 固定映射：
   - `docker unavailable` -> `ADVISORY`
   - `optional-unavailable` -> `PARTIAL`
   - `windows=0` -> `PARTIAL`
   - `kernel_log_empty_connections_probe=200` -> `PARTIAL`
3. `certify` profile 强制：
   - 非空 secret
   - `allow-existing-system-proxy=0`
   - `allow-real-proxy-coexist=0`
4. 固定端口改成运行时生成 `port_map`
5. 结束后必须做 leak assertion
6. 日常执行显式拆分为：
   - `daily-core`：默认，不运行真实 GUI，不触碰宿主机系统代理
   - `daily-host-gui`：显式 opt-in，允许真实 GUI / 系统代理验证

## 5. Wave C：恢复长跑的决策门

只有以下条件全部满足，才允许恢复 `nightly`：

1. 活跃文档与生成物里不再存在虚高 PASS / parity 结论。
2. `capabilities.json` 新 schema 生成通过，claim guard 通过。
3. 边界检查通过，且没有新增 bridge / global-registry 违规。
4. `daily` profile 在新 taxonomy 下完成一次本地 smoke，并输出完整 manifest。
5. 连续两次 back-to-back 运行后无残留端口、无残留进程组。

`certify` 不直接恢复：

1. 先恢复一次 24h `nightly`
2. 只有在该 `nightly` 证据包本地完整保留、mandatory gates 均为 `PROVEN`、且 GUI/contract 无 `PARTIAL` 冒充 PASS 时，才进入 `certify` 决策

## 5.1 协议 parity 收口（Phase 4 后半段）

这部分不属于 `nightly/certify` 长跑，而属于“替换 Go sing-box 的产品证据补齐”。

优先级：

1. `trojan`：已有较多 Rust 单边验证，优先补 Go/Rust 双核本地模拟公网对照
2. `shadowsocks`：已有 AEAD/UDP/多用户验证，优先补 Go/Rust 双核本地模拟公网对照
3. `shadowtls`：当前仍偏 config/smoke，先补真实 e2e，再决定是否进入双核 parity

## 6. 口径与默认值

1. 当前 slim snapshot 下，缺失本地 batch 工件的结论统一记为 `UNVERIFIED (slim snapshot)`。
2. Phase 4 只清理活跃入口与活跃生成物；archive 保留历史属性。
3. 本轮边界整改目标是 containment，不是一次性完成 contract crate 重构或彻底移除 `CONTEXT_REGISTRY`。
4. 本轮没有对外 API 变更要求；重点在证据 schema、运行入口、边界 policy、L18 harness。
