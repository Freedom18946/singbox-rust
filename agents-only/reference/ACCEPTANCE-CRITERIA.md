# 验收标准（Acceptance Criteria）

> 本文档定义当前维护模式下仍然有效的验收口径。  
> 注意：closure、capability state、behavior evidence 是三件不同的事，不能互相替代。

---

## 0. 验收状态分级

| 状态 | 定义 | 适用场景 | 证据要求 |
|------|------|---------|---------|
| `PASS-STRICT` | 全部步骤通过，且无 SKIP/环境豁免 | 完整可控环境 | 命令、日志、结果完整 |
| `PASS-ENV-LIMITED` | 主链路通过，但存在明确环境限制导致的 SKIP/降级 | 沙箱、权限受限、非目标平台 | 必须记录受限原因、原始输出、日志路径 |
| `FAIL` | 关键步骤失败且不可被环境限制解释 | 任意环境 | 记录失败点和修复方向 |

`PASS-ENV-LIMITED` 只用于环境不可得，不可替代功能缺陷。

## 0.1 Capability State Model

`reports/capabilities.json` 使用以下字段：

| 字段 | 枚举 |
|------|------|
| `compile_state` | `supported | gated_off | stubbed | absent` |
| `runtime_state` | `verified | unverified | unsupported | blocked` |
| `verification_state` | `e2e_verified | integration_verified | compile_only | no_evidence` |
| `overall_state` | `implemented_verified | implemented_unverified | scaffold_stub` |

判定规则：

1. `compile_state in {stubbed, absent}` -> `scaffold_stub`
2. `runtime_state in {unsupported, blocked}` -> `scaffold_stub`
3. `verification_state in {e2e_verified, integration_verified}` 且 `runtime_state=verified` -> `implemented_verified`
4. 其他可运行但证据不足 -> `implemented_unverified`

最小证据要求：

- 每个 capability 至少 1 条 `evidence`
- 单条格式：`{kind,path,line,note}`
- `kind` 常用值：`code | test | doc`

## 0.2 Closure 与行为证据的关系

- `GO_PARITY_MATRIX.md` 记录的是 closure / matrix 口径
- `reports/capabilities.json` 记录的是 capability tri-state
- 强完成度声明必须落到行为级证据，不能只靠矩阵或文档文字闭环

---

## 1. 功能对齐验收

### 1.1 总体指标

| 指标 | 目标 | 当前口径 | 证据要求 |
|------|------|---------|---------|
| 收口状态 | `Remaining = 0` | `209/209 closed`（acceptance baseline；含 accepted limitations / de-scoped 决策） | `GO_PARITY_MATRIX.md` + 对应历史/行为证据 |
| 行为级能力声明 | 高风险声明必须有行为证据 | 不允许仅靠 closure 矩阵证明“全部行为完全对齐” | capability evidence + 可执行验证 |
| Inbound / Outbound / DNS / Rules | 保持矩阵与实现说明一致 | 具体项见 `GO_PARITY_MATRIX.md` | 测试、运行、限制说明 |

### 1.2 协议验收检查表

对任何“已实现 / 已验证”协议，至少应满足：

- 配置解析正确
- 构造 / 注册路径可达
- 基本握手或实例化路径通过
- 错误处理与限制说明明确
- 若存在平台/权限限制，必须显式标注

---

## 2. 架构验收

### 2.1 边界门禁

```bash
./agents-only/06-scripts/check-boundaries.sh
```

预期：

- exit 0 才算 `PASS-STRICT`
- `--report` 可作为预检，但不能代替严格门禁

### 2.2 当前架构归属规则

| 条目 | 验收标准 |
|------|---------|
| `sb-core` | 内核合集层；路由/策略/编排为核心，保留模块必须 feature-gated 并受边界门禁约束 |
| 新协议实现 | 默认进入 `sb-adapters/` |
| 平台能力 | 归属 `sb-platform/`；`sb-core` 允许保留编排/调用层逻辑 |
| `sb-adapters -> sb-core` | 按预算与路径分类管理，不按旧宪法“一律违规”处理 |

### 2.3 ADR 一致性

| 条目 | 验收标准 |
|------|---------|
| ADR 对齐 | 存在 `agents-only/04-decisions/ADR-L19.3.1-sb-core-role.md` 且当前 reference 文档不再使用旧纯引擎层口径 |
| 文档对齐 | `ARCHITECTURE-SPEC.md`、`GLOSSARY.md`、`07-DEPENDENCY-AUDIT.md` 口径一致 |
| 门禁对齐 | `boundary-policy.json` 与 `check-boundaries.sh` 描述一致 |

---

## 3. 可测试性验收

### 3.1 单元/库级测试

| Crate | 验证命令 |
|-------|---------|
| `sb-core` | `cargo test -p sb-core --lib` |
| `sb-types` | `cargo test -p sb-types` |
| `sb-config` | `cargo test -p sb-config` |

### 3.2 当前有效的协议/集成测试目标

```bash
cargo test -p sb-adapters --features adapter-shadowsocks --test shadowsocks_integration
cargo test -p sb-adapters --features adapter-trojan --test trojan_integration
cargo test -p sb-adapters --features adapter-vless --test vless_integration
cargo test -p app --features net_e2e --test dns_outbound_e2e
```

说明：

- 前三者是 `sb-adapters` 下的 feature-gated test target
- DNS outbound 当前有效目标是 `dns_outbound_e2e`，不是旧文档中的 `dns_outbound_integration`

### 3.3 基础质量门禁

```bash
cargo fmt --check
cargo clippy --workspace --all-features -- -D warnings
cargo test --workspace
```

---

## 4. 性能验收

当前性能验收采用 `scripts/test/bench/l19_perf_acceptance.sh` 的分层契约，不再使用口号式结论。

统一入口：

```bash
bash scripts/test/bench/l19_perf_acceptance.sh --layer all
```

要求：

- 产出固定 JSON / CSV 结果
- 记录命令、退出码、日志和产物路径
- 若为 `PASS-ENV-LIMITED`，必须写明原因

对外文档不得手工抄写“性能已达标”结论而不附产物来源。

---

## 5. 安全验收

```bash
cargo deny check advisories
cargo deny check licenses
```

附加要求：

- 密钥与 token 不得在日志中裸出
- TLS 基线保持 1.2+
- 安全结论必须与 `reports/security_audit.md` 及相关 artifact 一致

---

## 6. 本地收口验收流程

```bash
./agents-only/06-scripts/check-boundaries.sh
cargo fmt --check
cargo clippy --workspace --all-features -- -D warnings
cargo test --workspace
cargo build -p app --features parity --release
./target/release/app version
./target/release/app check -c test_config.json
```

说明：

- 本仓库不再使用 GitHub Actions 作为当前验收口径
- 所有自动化验收表述都应以本地可执行命令链为主

---

*下一步：阅读 [ARCHITECTURE-SPEC.md](./ARCHITECTURE-SPEC.md) 了解当前架构规范*
