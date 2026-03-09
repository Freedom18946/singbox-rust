<!-- tier: A -->
# L18 Phase 4 工作包：全局静态审议整改

状态：🔄 进行中
更新：2026-03-09

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

## 6. 口径与默认值

1. 当前 slim snapshot 下，缺失本地 batch 工件的结论统一记为 `UNVERIFIED (slim snapshot)`。
2. Phase 4 只清理活跃入口与活跃生成物；archive 保留历史属性。
3. 本轮边界整改目标是 containment，不是一次性完成 contract crate 重构或彻底移除 `CONTEXT_REGISTRY`。
4. 本轮没有对外 API 变更要求；重点在证据 schema、运行入口、边界 policy、L18 harness。
