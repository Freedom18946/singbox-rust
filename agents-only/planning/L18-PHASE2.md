<!-- tier: S -->
# L18 Phase 2 详细工作包：Post-MIG-02 开封首跑

状态：🆕 规划冻结（待执行）
更新：2026-03-07

> **强制参考**：本文件所有双核/差分/覆盖率工作必须引用 `labs/interop-lab/docs/dual_kernel_golden_spec.md`（简称 **Golden Spec**）。
> 偏差归因→S4，diff 解读→S2+S3，case promote→S5，覆盖率→S6，Go 配置→S8。

---

## 1. Phase 2 目标与边界

### 1.1 主目标

MIG-02 大验收已通过 ACCEPTED（2026-03-07，Step 0-5 全绿，541 V7 assertions）。
L18 框架脚本（preflight / build_go_oracle / run_dual_kernel_cert / gui_real_cert / perf_gate / l18_capstone）已全部就绪、daily convergence 已验证（3 轮 PASS + 48x 高压排练 PASS），但 **从未在 MIG-02 后的代码基线上完整端到端跑通**。

Phase 2 目标是 **"开封跑通"**：

1. 在 MIG-02 后的代码基线上首次端到端执行 L18 全链路。
2. 发现并记录所有因 MIG-02 变更（隐式回退消除、env-var 严格化、route.final 必需化）导致的 L18 阻塞项。
3. 修复适配问题，建立可重跑的 MIG-02 后基线。
4. 为 nightly/certify 级别运行提供稳定起点。

### 1.2 非目标

- 不承诺完成 nightly 24h 或 certify 7d 级别运行（那是 Phase 3）。
- 不新增 L18 脚本功能；仅修复现有脚本与 MIG-02 后行为的不匹配。
- 不变更 L18 门禁阈值（p95 ≤ +5%、RSS ≤ +10%、startup ≤ +10%）。

### 1.3 输入前提

| 前提 | 来源 | 状态 |
|------|------|------|
| MIG-02 ACCEPTED | `agents-only/active_context.md` Step 0-5 | ✅ 2026-03-07 |
| V7 断言 541 条 | `check-boundaries.sh --strict` | ✅ exit 0 |
| 五项核心门禁全绿 | boundaries / parity / test / fmt / clippy | ✅ |
| L18 daily 3 轮 PASS | `reports/L18_REPLACEMENT_CERTIFICATION.md` §Daily capstone | ✅ |
| 48x 高压排练 PASS | `reports/l18/batches/20260227T054642Z-*` | ✅ |

### 1.4 成功标准

- `scripts/l18/l18_capstone.sh --profile daily` 在 MIG-02 后代码基线上获得 `PASS`（或 `PASS_ENV_LIMITED`）。
- 所有发现的阻塞项有明确的修复提交或降级策略记录。
- `reports/l18/phase2_baseline.lock.json` 锁定 Phase 2 基线。

---

## 2. 批次总览

| Batch | 主题 | WP 数 | 依赖 | 预计复杂度 |
|-------|------|--------|------|-----------|
| **E** | 环境开封与基线固化 | 3 | 无 | 低 |
| **F** | MIG-02 后适配审计 | 3 | E | 中 |
| **G** | Rust 单核认证首跑 | 3 | E + F | 中 |
| **H** | 双核差分首跑 | 3 | E + F + G | 中 |
| **I** | GUI 替换首跑 | 3 | H | 中-高 |
| **J** | Capstone 首跑与基线锁定 | 3 | G + H + I | 中 |

**总计**：18 个工作包

> 命名续接 Phase 1 的 Batch A-D（已在 `12-L18-REPLACEMENT-CERTIFICATION-WORKPACKAGES.md` 中定义）。

---

## 3. Batch E — 环境开封与基线固化

### WP-E1: Preflight 重跑与环境快照

| 字段 | 值 |
|------|-----|
| **复杂度** | 低 |
| **优先级** | P0 |
| **依赖** | 无 |

**内容**：

1. 在 MIG-02 后的 main HEAD 上执行 preflight：
   ```bash
   scripts/l18/preflight_macos.sh \
     --require-docker 0 \
     --gui-path <GUI_APP_ROOT>
   ```
2. 验证 `reports/l18/baseline.lock.json` 输出完整，记录 git SHA、工具链版本、端口可用性。
3. 记录环境快照到 `reports/l18/phase2/env_snapshot.json`。

**交付**：
- `reports/l18/baseline.lock.json`（刷新）
- `reports/l18/phase2/env_snapshot.json`（新建）

**验收**：
- preflight exit 0
- baseline.lock.json 中 `git_sha` 匹配当前 main HEAD
- 所有必需端口（9090/19090/11810/11811）空闲

---

### WP-E2: Rust parity 二进制构建确认

| 字段 | 值 |
|------|-----|
| **复杂度** | 低 |
| **优先级** | P0 |
| **依赖** | 无 |

**内容**：

1. 在 MIG-02 后代码基线上构建 parity 二进制：
   ```bash
   cargo build --release -p app --features parity --bin run
   ```
2. 验证二进制存在且可启动（`--help` 退出码 0）。
3. 验证五项核心门禁：
   ```bash
   cargo fmt --all -- --check
   cargo clippy --workspace --all-features --all-targets -- -D warnings
   cargo test --workspace
   cargo check -p app --features parity
   make boundaries
   ```

**交付**：
- `target/release/run`（二进制）
- Phase 2 构建日志

**验收**：
- 二进制文件存在且可执行
- 五项门禁全部 exit 0

---

### WP-E3: Go Oracle 构建确认

| 字段 | 值 |
|------|-----|
| **复杂度** | 低 |
| **优先级** | P0 |
| **依赖** | 无 |

**内容**：

1. 执行 Go Oracle 构建：
   ```bash
   scripts/l18/build_go_oracle.sh \
     --go-source-dir go_fork_source/sing-box-1.12.14 \
     --build-tags with_clash_api
   ```
2. 验证 `oracle_manifest.json` 完整（包含 go_version、build_tags、sha256）。
3. 确认 Go 二进制能正常启动并监听 Clash API（`:9090`）。

**交付**：
- `reports/l18/oracle/go/<run_id>/sing-box`
- `reports/l18/oracle/go/<run_id>/oracle_manifest.json`

**验收**：
- build_go_oracle.sh exit 0
- oracle_manifest.json 存在且 JSON 合法
- Go 二进制启动后 `curl http://127.0.0.1:9090` 可达

---

## 4. Batch F — MIG-02 后适配审计

### WP-F1: L18 配置文件 route.final 审计

| 字段 | 值 |
|------|-----|
| **复杂度** | 中 |
| **优先级** | P0 |
| **依赖** | E1 |

**内容**：

MIG-02 消除了隐式直连回退：缺少 `route.final` 的配置将导致 "unresolved" 而非静默 direct。所有 L18 配置必须显式声明 `route.final`。

1. 审计所有 L18 配置文件：
   - `labs/interop-lab/configs/l18_gui_rust.json` — 已有 `"final": "my-group"` ✅
   - `labs/interop-lab/configs/l18_gui_go.json` — 已有 `"final": "my-group"` ✅
   - `labs/interop-lab/configs/l18_perf_rust.json` — 已有 `"final": "direct"` ✅
   - `labs/interop-lab/configs/l18_perf_go.json` — 已有 `"final": "direct"` ✅
2. 审计 capstone 脚本中内联/动态生成的配置片段：
   - `l18_capstone.sh` 中的 canary config
   - `run_capstone_fixed_profile.sh` 中的 canary bootstrap config
3. 审计所有 `scripts/l18/fixtures/` 下的配置。
4. 对每个配置运行 `cargo run -p app --features parity --bin run -- check -c <config>` 验证解析通过。

**交付**：
- `reports/l18/phase2/config_route_final_audit.md`（审计清单 + 结果）

**验收**：
- 所有 L18 配置均有显式 `route.final`
- `check` 命令对每个配置 exit 0

---

### WP-F2: Env-var 严格化影响审计

| 字段 | 值 |
|------|-----|
| **复杂度** | 中 |
| **优先级** | P1 |
| **依赖** | E1 |

**内容**：

MIG-02 wave#123-198 将所有 env-var silent parse fallback 转为显式失败/warn。L18 脚本中设置的环境变量需确认不触发新的失败路径。

1. 列出 L18 脚本中所有 `export` / `L18_*` / `INTEROP_*` 环境变量。
2. 对每个变量，确认：
   - 变量值类型与 Rust 代码 parse 期望一致
   - 变量缺失时的行为是预期的（warn 而非 FAIL）
3. 重点检查项：
   - `L18_GUI_TIMEOUT_SEC` — 应为合法 u64
   - `L18_RUST_BUILD_ENABLED` / `L18_GUI_GO_BUILD_ENABLED` / `L18_GUI_RUST_BUILD_ENABLED` — 应为 `0` 或 `1`
   - `INTEROP_GO_API_BASE` / `INTEROP_GO_API_TOKEN` — 空值行为
   - `L18_CANARY_API_URL` — 应为合法 URL

**交付**：
- `reports/l18/phase2/env_var_audit.md`

**验收**：
- 所有 L18 环境变量值与 MIG-02 后代码期望兼容
- 无 silent fallback 残留（V7 断言已覆盖）

---

### WP-F3: 隐式回退消除对 L18 链路的影响评估

> **Golden Spec 引用**：使用 S4 偏差注册表（DIV-C-001 无隐式直连回退、DIV-C-002 SOCKS5 UDP）验证配置兼容性。

| 字段 | 值 |
|------|-----|
| **复杂度** | 中 |
| **优先级** | P0 |
| **依赖** | E2, F1 |

**内容**：

MIG-02 wave#200-202 消除了 inbound handler / tailscale 中的隐式直连回退。评估这些变更对 L18 双核差分、GUI 认证和 perf gate 的影响。

1. 核查 L18 configs 中使用的 inbound 类型：
   - `socks`（L18 默认 inbound）— 受 MIG-02 影响：router 为 None 时不再 direct fallback
   - 确认 L18 configs 已提供 `route.final`，使 socks inbound 有路由可用
2. 核查 L18 configs 是否涉及 tailscale outbound：
   - 不涉及（L18 仅用 direct/selector）— **无影响**
3. 核查双核差分中 Go 与 Rust 的行为一致性：
   - Go: 有 default outbound 解析链（explicit tag → first → direct fallback）
   - Rust (MIG-02 后): 无隐式回退，`route.final` 必需
   - 两者均使用 `"final": "my-group"` → 行为应一致
4. 文档化所有发现，标记需修复项和无影响项。

**交付**：
- `reports/l18/phase2/mig02_impact_assessment.md`

**验收**：
- 影响评估覆盖所有 MIG-02 wave#200-202 变更路径
- 需修复项全部有对应的修复 WP 或确认无影响

---

## 5. Batch G — Rust 单核认证首跑

### WP-G1: Rust 内核启动 + Clash API 可达性验证

| 字段 | 值 |
|------|-----|
| **复杂度** | 低-中 |
| **优先级** | P0 |
| **依赖** | E2, F1, F3 |

**内容**：

1. 使用 Phase 2 构建的 parity 二进制启动 Rust 内核：
   ```bash
   target/release/run run -c labs/interop-lab/configs/l18_gui_rust.json &
   RUST_PID=$!
   ```
2. 验证 Clash API 可达：
   ```bash
   curl -s -H "Authorization: Bearer test-secret" \
     http://127.0.0.1:19090/proxies | jq '.proxies | length'
   ```
3. 验证 SOCKS inbound 可达：
   ```bash
   curl -x socks5h://127.0.0.1:11810 http://httpbin.org/ip
   ```
4. 干净关停（SIGTERM）并验证端口释放。

**交付**：
- Phase 2 首跑日志（stdout/stderr 保存到 `reports/l18/phase2/rust_solo/`）
- 可达性验证结果

**验收**：
- Clash API 返回 200 且 proxies 列表非空
- SOCKS 代理请求成功（或标记 `ENV_LIMITED` 如无外网）
- SIGTERM 后端口 19090/11810 释放

---

### WP-G2: Interop-lab Rust 全量 case 验证

| 字段 | 值 |
|------|-----|
| **复杂度** | 中 |
| **优先级** | P1 |
| **依赖** | G1 |

**内容**：

1. 执行 interop-lab 单元测试（已在 MIG-02 验收 Step 3 通过，此处重跑确认）：
   ```bash
   cargo test -p interop-lab
   ```
2. 如有失败，分析是否因 MIG-02 后行为变更导致，归因并记录。

**交付**：
- interop-lab 测试输出日志
- 失败归因文档（如有）

**验收**：
- 27+ 测试全部 passed（与 MIG-02 验收 Step 3 一致）
- 无新增失败

---

### WP-G3: Workspace 全量测试 + 稳定性测试

| 字段 | 值 |
|------|-----|
| **复杂度** | 中 |
| **优先级** | P1 |
| **依赖** | G1 |

**内容**：

1. 全量 workspace 测试：
   ```bash
   cargo test --workspace
   ```
2. 热重载稳定性（MIG-02 验收已确认 20x PASS）：
   ```bash
   cargo test -p app --features "parity,long_tests" \
     --test hot_reload_stability -- --ignored --nocapture
   ```
   > 注：capstone 脚本中使用 `--features long_tests --test hot_reload_stability` + 预构建二进制路径。
   > 此处为独立执行命令，含 `parity` 以确保测试二进制包含完整功能。
3. 信号可靠性（MIG-02 验收已确认 5x PASS）：
   ```bash
   cargo test -p app --features "parity,long_tests" \
     --test signal_reliability -- --ignored --nocapture
   ```

**交付**：
- 测试输出日志
- 热重载/信号 PASS 日志

**验收**：
- workspace test 0 failed
- hot_reload 至少 5x PASS
- signal 至少 3x PASS

---

## 6. Batch H — 双核差分首跑

### WP-H1: Daily profile 双核差分执行

> **Golden Spec 引用**：diff 结果解读使用 S2（维度→BHV 映射）+ S3（行为注册表）定位具体行为 ID。失败项先查 S4 排除已知偏差。

| 字段 | 值 |
|------|-----|
| **复杂度** | 中 |
| **优先级** | P0 |
| **依赖** | E3, G1 |

**内容**：

1. 执行 daily 双核差分：
   ```bash
   scripts/l18/run_dual_kernel_cert.sh \
     --profile daily
   ```
2. 验证 summary.json 和 diff_gate.json 输出。
3. 核查 `run_fail_count` 和 `diff_fail_count` 均为 0。

**交付**：
- `reports/l18/dual_kernel/<run_id>/summary.json`
- `reports/l18/dual_kernel/<run_id>/diff_gate.json`

**验收**：
- 脚本 exit 0
- `run_fail_count == 0`
- `diff_fail_count == 0`
- `selected_case_count >= 5`（daily P0/P1 cases）

---

### WP-H2: 差分结果 MIG-02 适配分析

> **Golden Spec 引用**：每个差异项必须映射到 BHV-ID（S3），归因时交叉检查 S4 偏差注册表（12 项已知偏差）。

| 字段 | 值 |
|------|-----|
| **复杂度** | 中 |
| **优先级** | P1 |
| **依赖** | H1 |

**内容**：

1. 对比 Phase 2 双核差分结果与 Phase 1 基线（`20260226T015945Z-daily-dc0b3935`）。
2. 检查是否有新的差异项因 MIG-02 变更引入：
   - 错误码变化（原 silent fallback → 现 explicit error）
   - 响应延迟变化（移除了回退路径后的行为差异）
   - 新的 FAIL case（原 PASS → 现 FAIL）
3. 对每个差异项归因：MIG-02 引入 vs 环境差异 vs 已知 flake。

**交付**：
- `reports/l18/phase2/dual_kernel_diff_analysis.md`

**验收**：
- 所有差异项有明确归因
- 无未解释的新 FAIL case

---

### WP-H3: Nightly profile 双核差分试跑

| 字段 | 值 |
|------|-----|
| **复杂度** | 中 |
| **优先级** | P2 |
| **依赖** | H1, H2 |

**内容**：

1. 执行 nightly 双核差分（全量 both-kernel cases）：
   ```bash
   scripts/l18/run_dual_kernel_cert.sh \
     --profile nightly
   ```
2. 记录结果并与 daily 对比，确认扩展 case 集无额外阻塞。

**交付**：
- `reports/l18/dual_kernel/<run_id>/summary.json`
- `reports/l18/dual_kernel/<run_id>/diff_gate.json`

**验收**：
- 脚本 exit 0 或标记已知 ENV_LIMITED
- `diff_fail_count == 0`（或所有 FAIL 有归因）

---

## 7. Batch I — GUI 替换首跑

### WP-I1: GUI 单核 Rust 认证首跑

| 字段 | 值 |
|------|-----|
| **复杂度** | 中-高 |
| **优先级** | P0 |
| **依赖** | H1 |

**内容**：

1. 执行 GUI 真实认证（Rust 单核）：
   ```bash
   scripts/l18/gui_real_cert.sh \
     --gui-app <GUI_APP_PATH> \
     --rust-bin target/release/run \
     --rust-config labs/interop-lab/configs/l18_gui_rust.json \
     --rust-api-url http://127.0.0.1:19090 \
     --rust-build-enabled 0 \
     --go-build-enabled 0 \
     --timeout-sec 120 \
     --allow-existing-system-proxy 1 \
     --allow-real-proxy-coexist 1
   ```
2. 验证五步关键流全部 PASS：`startup → load_config → switch_proxy → connections_panel → logs_panel`。
3. 如 GUI 交互失败，收集诊断信息：
   - API 可达性日志
   - GUI 进程 stdout/stderr
   - 端口占用快照

**交付**：
- `reports/l18/gui_real_cert.json`
- `reports/l18/gui_real_cert.md`
- 故障诊断包（如有失败）

**验收**：
- 五步关键流全部 `PASS`
- Rust API 返回 `/proxies=200`
- 系统代理快照前后一致

---

### WP-I2: GUI 双核对比认证

| 字段 | 值 |
|------|-----|
| **复杂度** | 中-高 |
| **优先级** | P1 |
| **依赖** | I1 |

**内容**：

1. 执行 GUI 双核认证（Go + Rust 顺序运行）：
   ```bash
   scripts/l18/gui_real_cert.sh \
     --gui-app <GUI_APP_PATH> \
     --go-bin go_fork_source/sing-box-1.12.14/sing-box \
     --go-config labs/interop-lab/configs/l18_gui_go.json \
     --go-api-url http://127.0.0.1:9090 \
     --go-build-enabled 0 \
     --rust-bin target/release/run \
     --rust-config labs/interop-lab/configs/l18_gui_rust.json \
     --rust-api-url http://127.0.0.1:19090 \
     --rust-build-enabled 0 \
     --timeout-sec 120 \
     --allow-existing-system-proxy 1 \
     --allow-real-proxy-coexist 1
   ```
2. 对比 Go 和 Rust 的 GUI 五步结果。
3. 确认双核行为一致。

**交付**：
- GUI 双核认证报告
- 行为差异分析（如有）

**验收**：
- Go 和 Rust 五步全部 `PASS`
- `/proxies` API 均返回 200
- 无行为差异或差异已归因

---

### WP-I3: GUI Sandbox 不扰民验证

| 字段 | 值 |
|------|-----|
| **复杂度** | 中 |
| **优先级** | P1 |
| **依赖** | I1 |

**内容**：

验证 L18 沙盒不扰民设计在 MIG-02 后仍然有效。

1. 系统代理保护验证：
   - 记录 `scutil --proxy` 快照 → 运行 GUI 认证 → 再次快照 → 字节级对比
2. 临时 sandbox HOME 验证：
   - 确认 GUI 在独立 sandbox 目录运行，不读写用户常规配置
3. 进程回收验证：
   - 确认仅回收本次 run 启动的 PID
   - 确认关键端口运行后释放
4. Loopback 边界验证：
   - 所有通信仅 127.0.0.1/localhost/::1

**交付**：
- sandbox 验证日志
- 系统代理快照对比结果

**验收**：
- 系统代理前后快照一致
- sandbox HOME 独立
- 所有端口运行后释放
- 无 `0.0.0.0` 监听

---

## 8. Batch J — Capstone 首跑与基线锁定

### WP-J1: Daily Capstone 首跑（MIG-02 后）

| 字段 | 值 |
|------|-----|
| **复杂度** | 中 |
| **优先级** | P0 |
| **依赖** | G3, H1, I1 |

**内容**：

1. 使用固定配置执行 daily capstone：
   ```bash
   scripts/l18/run_capstone_fixed_profile.sh \
     --profile daily \
     --gui-app <GUI_APP_PATH> \
     --require-docker 0 \
     --workspace-test-threads 1 \
     --allow-existing-system-proxy 1 \
     --allow-real-proxy-coexist 1
   ```
2. 固定配置基线（不可漂移）：
   - `L18_GUI_TIMEOUT_SEC=120`
   - `L18_RUST_BUILD_ENABLED=0`
   - `L18_GUI_GO_BUILD_ENABLED=0`
   - `L18_GUI_RUST_BUILD_ENABLED=0`
   - Rust binary: `target/release/run`（预构建 parity）
3. 验证所有门禁结果。

**预期门禁结果**：

| 门禁 | 预期 | 说明 |
|------|------|------|
| boundaries | PASS | MIG-02 验收已确认 |
| parity | PASS | E2 已确认 |
| workspace_test | PASS | G3 已确认 |
| fmt | PASS | MIG-02 验收已确认 |
| clippy | PASS | MIG-02 验收已确认 |
| hot_reload | PASS | G3 已确认 |
| signal | PASS | G3 已确认 |
| docker | WARN/ENV_LIMITED | 无 Docker daemon 时 |
| gui_smoke | PASS | I1 已确认 |
| canary | PASS | 1h canary |
| dual_kernel_diff | PASS | H1 已确认 |
| perf_gate | PASS | 需实测 |

**交付**：
- `reports/l18/l18_capstone_status.json`
- 批次产物目录（config.freeze.json + precheck.txt）

**验收**：
- overall 为 `PASS` 或 `PASS_ENV_LIMITED`（仅 docker 项可为 ENV_LIMITED）
- 所有非 docker 门禁为 PASS

---

### WP-J2: 性能门禁首跑

| 字段 | 值 |
|------|-----|
| **复杂度** | 中 |
| **优先级** | P0 |
| **依赖** | E2, E3 |

**内容**：

1. 执行性能门禁对比：
   ```bash
   scripts/l18/perf_gate.sh \
     --go-bin go_fork_source/sing-box-1.12.14/sing-box \
     --go-config labs/interop-lab/configs/l18_perf_go.json \
     --rust-bin target/release/run \
     --rust-config labs/interop-lab/configs/l18_perf_rust.json \
     --perf-rounds 3 \
     --p95-threshold-pct 5 \
     --rss-threshold-pct 10 \
     --startup-threshold-pct 10
   ```
2. 分析 MIG-02 后性能是否有回归：
   - 隐式回退路径移除 → 理论上不应影响 direct 性能
   - env-var 严格化 → warn 日志可能有微量开销

**交付**：
- `reports/l18/perf_gate.json`
- 性能对比分析（如有回归）

**验收**：
- p95 latency ≤ Go + 5%
- RSS peak ≤ Go + 10%
- startup time ≤ Go + 10%
- 脚本 exit 0

---

### WP-J3: Phase 2 基线锁定与文档归档

> **Golden Spec 引用**：使用 S6 覆盖率仪表盘记录 Phase 2 覆盖率快照。更新 S3/S6 中的覆盖数据如有 case promote。

| 字段 | 值 |
|------|-----|
| **复杂度** | 低 |
| **优先级** | P0 |
| **依赖** | J1, J2 |

**内容**：

1. 锁定 Phase 2 基线：
   - 生成 `reports/l18/phase2_baseline.lock.json`（git SHA + capstone 结果 + 性能数据 + 门禁状态）
   - 与 Phase 1 基线对比，标注所有变化点
2. 归档 Phase 2 产物：
   - 所有审计报告（F1/F2/F3）
   - 所有首跑日志（G/H/I/J）
   - capstone_status.json
3. 更新状态文档：
   - `reports/L18_REPLACEMENT_CERTIFICATION.md` — 添加 Phase 2 章节
   - `agents-only/active_context.md` — 更新执行焦点
   - `agents-only/workpackage_latest.md` — 更新下一阶段评估

**交付**：
- `reports/l18/phase2_baseline.lock.json`
- 更新后的状态文档

**验收**：
- Phase 2 基线与 Phase 1 基线可追溯对比
- 状态文档与实际结果一致
- 下一步行动清晰（Phase 3: nightly/certify 级别运行）

---

## 9. MIG-02 后适配审计清单

以下清单覆盖 MIG-02 所有变更路径与 L18 脚本的交集。

### 9.1 route.final 必需化

| 审计项 | 配置文件 | 现状 | 操作 |
|--------|----------|------|------|
| GUI Rust config | `l18_gui_rust.json` | `"final": "my-group"` ✅ | 无需修改 |
| GUI Go config | `l18_gui_go.json` | `"final": "my-group"` ✅ | 无需修改 |
| Perf Rust config | `l18_perf_rust.json` | `"final": "direct"` ✅ | 无需修改 |
| Perf Go config | `l18_perf_go.json` | `"final": "direct"` ✅ | 无需修改 |
| Capstone canary config | 脚本内联生成 | 需审计 | WP-F1 |
| Dual kernel cases | interop-lab cases | 需审计 | WP-F1 |

### 9.2 隐式回退消除

| 变更路径 | 影响的 inbound 类型 | L18 是否涉及 | 影响评估 |
|----------|---------------------|-------------|----------|
| Trojan/VLess/VMess inbound | W200 | 不涉及 | 无影响 |
| SS/STls/AnyTls inbound | W200 | 不涉及 | 无影响 |
| Redirect/TProxy inbound | W200 | 不涉及（沙盒禁止） | 无影响 |
| SOCKS5 UDP enhanced | W201 | 可能涉及 | 需确认 socks inbound 路由 |
| TUN macOS | W201 | 不涉及（沙盒禁止） | 无影响 |
| Tailscale outbound modes | W202 | 不涉及 | 无影响 |

### 9.3 Env-var 严格化

| 变量类别 | 影响范围 | L18 使用场景 | 风险 |
|----------|----------|-------------|------|
| `SB_*` 运行时 env | Rust 内核运行时 | 默认值即可 | 低（L18 不设自定义 SB_* 值） |
| `L18_*` 脚本 env | 脚本参数传递 | 构建/运行控制 | 低（值为 0/1/URL 等标准类型） |
| `INTEROP_*` env | interop-lab 集成 | 双核差分 | 中（空值需确认不触发失败） |

---

## 10. 环境前置检查清单

在执行 Batch E 之前，运行以下检查：

```bash
# 1. 确认代码基线
git log --oneline -3  # 应看到 MIG-02 验收提交

# 2. 确认 V7 门禁
make boundaries  # exit 0, 541 assertions

# 3. 确认工具链
go version        # go1.22+
rustc --version   # rustc 1.80+
cargo --version
jq --version
python3 --version
lsof -v 2>&1 | head -1
curl --version | head -1

# 4. 确认端口空闲
for p in 9090 19090 11810 11811 29090; do
  lsof -i :$p && echo "PORT $p OCCUPIED" || echo "PORT $p FREE"
done

# 5. 确认 GUI.for.SingBox 可访问
ls -la <GUI_APP_PATH>/Contents/MacOS/

# 6. 确认 Go 源码可访问
ls go_fork_source/sing-box-1.12.14/main.go
```

---

## 11. 预期阻塞项与降级策略

| # | 预期阻塞 | 概率 | 降级策略 |
|---|----------|------|----------|
| B1 | Docker daemon 不可用 | 高 | `--require-docker 0`，docker 门禁标记 `ENV_LIMITED` |
| B2 | GUI.for.SingBox 版本不匹配 | 低 | 使用已验证版本（1.19.0），不升级 |
| B3 | Capstone canary 内联 config 缺少 `route.final` | 中 | WP-F1 中修复，补入 `"final": "direct"` |
| B4 | 外网不可达导致 SOCKS 代理功能测试失败 | 中 | 标记 `ENV_LIMITED`，不阻塞认证 |
| B5 | GUI 交互超时（`gui_or_kernel_not_ready`） | 低 | 已有 120s 超时 + 就绪轮询，Phase 1 已消除此 flake |
| B6 | 性能微回归（warn 日志开销） | 低 | 阈值宽裕（5%/10%/10%），可吸收微量开销 |
| B7 | Go Oracle 编译失败（Go 版本兼容） | 低 | 使用 Phase 1 已验证的 Go Oracle 二进制 |
| B8 | interop-lab case 与 MIG-02 后行为不匹配 | 低 | MIG-02 验收 Step 3 已确认 27 passed |

---

## 12. 执行建议

### 12.1 推荐执行顺序

```
E1 → E2 ──┐      E3 ──────────────────────┐
           ↓                                ↓
F1 → F2 → F3                               │
           ↓                                │
G1 → G2                                    │
G1 → G3                                    │
           ↓                                ↓
           H1 ─────────────────────────────→ J2
           ↓
           H2 → H3
           ↓
           I1 → I2
           I1 → I3
           ↓
           J1 → J3
```

### 12.2 快速路径（最小首跑）

若时间有限，可只执行：**E1 → E2 → E3 → F1 → G1 → H1 → I1 → J1 → J2 → J3**（10 WP），跳过 F2/F3/G2/G3/H2/H3/I2/I3。

### 12.3 首跑命令参考

```bash
# Preflight
scripts/l18/preflight_macos.sh --require-docker 0

# Build Rust parity binary
cargo build --release -p app --features parity --bin run

# Build Go Oracle
scripts/l18/build_go_oracle.sh \
  --go-source-dir go_fork_source/sing-box-1.12.14 \
  --build-tags with_clash_api

# Daily capstone (end-to-end)
scripts/l18/run_capstone_fixed_profile.sh \
  --profile daily \
  --gui-app /path/to/GUI.for.SingBox.app \
  --require-docker 0 \
  --workspace-test-threads 1 \
  --allow-existing-system-proxy 1 \
  --allow-real-proxy-coexist 1
```

---

## 13. 与 Phase 1 的关系

| 方面 | Phase 1 (Batch A-D) | Phase 2 (Batch E-J) |
|------|---------------------|---------------------|
| 代码基线 | MIG-02 之前 | MIG-02 之后 |
| 主目标 | 脚本开发 + daily 收敛 | 开封首跑 + 适配修复 |
| V7 断言 | 未引入 | 541 条 |
| 隐式回退 | 部分存在 | 全部消除 |
| 输出 | 脚本资产 + daily 3 轮 PASS | Phase 2 基线 + 适配审计 |
| 后续 | → Phase 2 | → Phase 3（nightly/certify） |

---

## 14. 引用

| 资产 | 路径 |
|------|------|
| **双核黄金基准（必引）** | **`labs/interop-lab/docs/dual_kernel_golden_spec.md`** |
| Phase 1 工作包 | `agents-only/03-planning/12-L18-REPLACEMENT-CERTIFICATION-WORKPACKAGES.md` |
| L18 认证报告 | `reports/L18_REPLACEMENT_CERTIFICATION.md` |
| L18 脚本目录 | `scripts/l18/` |
| L18 配置目录 | `labs/interop-lab/configs/l18_*.json` |
| MIG-02 验收记录 | `agents-only/active_context.md` §MIG-02 大验收 |
| V7 边界检查 | `agents-only/06-scripts/check-boundaries.sh` |
| 当前上下文 | `agents-only/active_context.md` |
| 工作包追踪 | `agents-only/workpackage_latest.md` |
