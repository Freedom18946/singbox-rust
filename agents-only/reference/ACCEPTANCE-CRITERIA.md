# 验收标准（Acceptance Criteria）

> **本文档定义所有可验证的验收条款**：通过这些标准即可确认实现符合需求。

---

## 0. 验收状态分级（L4 新增）

为避免“PASS 含义不清”，本项目统一采用双轨验收状态：

| 状态 | 定义 | 适用场景 | 证据要求 |
|------|------|---------|---------|
| `PASS-STRICT` | 全部步骤通过，且无 SKIP/环境豁免 | CI 或完整可控环境 | 命令、日志、结果均完整 |
| `PASS-ENV-LIMITED` | 主链路通过，但存在明确环境限制导致的 SKIP/降级 | 沙箱、权限受限、非目标平台 | 必须记录受限原因 + 原始命令输出 + 日志路径 |
| `FAIL` | 关键步骤失败且不可被环境限制解释 | 任意环境 | 记录失败点和修复建议 |

> `PASS-ENV-LIMITED` 仅用于“环境不可得”场景，不可替代功能缺陷。

### 0.1 能力三态模型（L19 Batch A）

为统一“实现状态/可运行状态/证据状态”的口径，`reports/capabilities.json` 采用以下四元字段：

| 字段 | 枚举 |
|------|------|
| `compile_state` | `supported | gated_off | stubbed | absent` |
| `runtime_state` | `verified | unverified | unsupported | blocked` |
| `verification_state` | `e2e_verified | integration_verified | compile_only | no_evidence` |
| `overall_state` | `implemented_verified | implemented_unverified | scaffold_stub` |

`overall_state` 判定规则（按优先级）：

1. `compile_state in {stubbed, absent}` -> `scaffold_stub`
2. `runtime_state in {unsupported, blocked}` -> `scaffold_stub`
3. `verification_state in {e2e_verified, integration_verified}` 且 `runtime_state=verified` -> `implemented_verified`
4. 其他可运行但证据不足 -> `implemented_unverified`

证据最小要求：

- 每个 capability 至少 1 条 `evidence`。
- 单条格式固定：`{kind,path,line,note}`。
- `kind` 推荐值：`code | test | doc | ci`。

---

## 1. 功能对齐验收（Parity Acceptance）

### 1.1 总体指标

| 指标 | 目标 | 当前 | 验收方式 |
|------|------|------|---------|
| 总体对齐率 | ≥ 95% | 100%（209/209 closed, acceptance baseline） | `GO_PARITY_MATRIX.md` |
| Inbound 协议 | 100% | 100% (18/18) | 功能测试 |
| Outbound 协议 | 100% | 100% (19/19) | 功能测试 |
| DNS 传输 | 100% | 100% (11/11) | 功能测试 |
| 路由规则 | 100% | 100% (38/38) | 规则匹配测试 |

### 1.2 协议验收检查表

```bash
# 每个协议需要通过以下验证：
□ 配置解析正确（JSON/YAML）
□ 握手成功（Client <-> Server）
□ 数据传输正确
□ 错误处理合理
□ 超时/重连逻辑正确
```

---

## 2. 架构验收（Architecture Acceptance）

### 2.1 依赖树验收

**✅ PASS 条件**：

```bash
# 架构依赖边界门禁（含：sb-core 源码引用 + Cargo.toml 直接依赖 optional + 反向依赖计数等）
./agents-only/06-scripts/check-boundaries.sh
# 预期：exit 0

# sb-api 不依赖 sb-adapters
cargo tree -p sb-api | grep "sb-adapters"
# 预期输出：无匹配
```

### 2.2 代码归属验收

| 条目 | 验收标准 |
|------|---------|
| 协议实现 | 新增协议默认在 `sb-adapters/`；`sb-core` 遗留实现必须 feature-gated 且在重叠清单有 owner |
| 平台服务 | 平台能力在 `sb-platform/`；`sb-core` 仅允许保留编排/调用层逻辑 |
| sb-core | 定位为内核合集层：路由/策略为核心，遗留协议/服务实现受边界门禁约束 |

### 2.3 L19.3.1 决议一致性验收

| 条目 | 验收标准 |
|------|---------|
| ADR 对齐 | 存在 `agents-only/04-decisions/ADR-L19.3.1-sb-core-role.md` 且状态为已批准 |
| 宪法口径 | `03-ARCHITECTURE-SPEC` 与 `01-REQUIREMENTS-ANALYSIS` 不再声明“sb-core 纯引擎层禁入 TLS/QUIC/Web” |
| 门禁口径 | `check-boundaries.sh` 可在当前决议口径下作为阻断门禁（exit 0/非 0） |

---

## 3. 可测试性验收（Testability Acceptance）

### 3.1 单元测试

| Crate | 要求 | 验证命令 |
|-------|------|---------|
| sb-core | 不依赖真实网络 | `cargo test -p sb-core --lib` |
| sb-types | 100% 纯逻辑 | `cargo test -p sb-types` |
| sb-config | Schema 验证 | `cargo test -p sb-config` |

### 3.2 集成测试覆盖

```bash
# 协议集成测试
cargo test --test shadowsocks_integration  # 14 tests
cargo test --test trojan_integration       # 16 tests
cargo test --test vless_integration        # 17 tests
cargo test --test dns_outbound_integration # 15 tests
```

---

## 4. 性能验收（Performance Acceptance）

### 4.1 统一测量契约（L19.4.3）

性能验收不再使用“口号型阈值”，统一采用分层 + 可复算命令 + 固定产物路径。

| 条目 | 固定定义 |
|------|---------|
| 分层 | `Baseline` / `Router+Clash API` / `Parity` |
| 统一入口 | `bash scripts/test/bench/l19_perf_acceptance.sh --layer all` |
| 百分位 | 统一输出 `P50/P95/P99`（毫秒） |
| 冷热定义 | `cold` = round 1；`warm` = round 2..N（不足 2 轮时退化为 round 1） |
| 平台范围 | `Darwin-arm64`（主） + `Linux-x86_64`（辅） |
| 统一产物根目录 | `reports/performance/l19/<run_id>/` |

统一指标定义：

1. `latency_ms`: 请求级延迟 `P50/P95/P99`。
2. `startup_ms`: 进程启动到就绪耗时（cold/warm 分开记录）。
3. `rss_peak_kb`: 运行期峰值 RSS。
4. `conn_rss_delta_bytes_per_conn`: 基于 `memory_comparison.json` 的连接规模 RSS 增量估算（100 / 1000 连接各一组）。

### 4.2 Layer A：Baseline（最小基准层）

| 维度 | 固定口径 |
|------|---------|
| 目的 | 仅测基础计算/协议路径，不引入 GUI 与 parity 全量特性干扰 |
| 特性集 | `cargo bench -p sb-benches`（协议基准） |
| 命令 | `bash scripts/test/bench/l19_perf_acceptance.sh --layer baseline` |
| 关键产物 | `baseline_protocol_percentiles.json`、`baseline_bench_summary.csv` |

通过条件：

1. 产出 `baseline_protocol_percentiles.json`，且每个协议具备 `p50/p95/p99`。
2. 产出 `baseline_bench_summary.csv`（无数据时允许 `PASS-ENV-LIMITED`，需写明原因）。

### 4.3 Layer B：Router+Clash API（GUI 实用层）

| 维度 | 固定口径 |
|------|---------|
| 目的 | 对齐 GUI 常用配置场景（非 parity 全特性） |
| 特性集 | `acceptance`（由 `scripts/l18/perf_gate.sh` 构建） |
| 命令 | `bash scripts/test/bench/l19_perf_acceptance.sh --layer router_api` |
| 关键产物 | `router_api_perf_gate.json`、`router_api_latency_percentiles.json`、`router_api_memory_comparison.json` |

通过条件：

1. `router_api_perf_gate.json` 可解析，包含 `startup_ms`、`latency_p95_ms`、`rss_peak_kb`。
2. `router_api_latency_percentiles.json` 输出 `cold/warm` 的 `P50/P95/P99`。
3. `router_api_memory_comparison.json` 可计算 `conn_rss_delta_bytes_per_conn`。

### 4.4 Layer C：Parity（全特性层）

| 维度 | 固定口径 |
|------|---------|
| 目的 | 验证 parity 特性集下的性能回归边界 |
| 特性集 | `parity`（由 `scripts/l18/perf_gate.sh` 构建） |
| 命令 | `bash scripts/test/bench/l19_perf_acceptance.sh --layer parity` |
| 关键产物 | `parity_perf_gate.json`、`parity_latency_percentiles.json`、`parity_memory_comparison.json` |

通过条件（继承 perf gate）：

1. `latency_p95` 回归 <= `+5%`（相对 Go 基线）。
2. `rss_peak` 回归 <= `+10%`。
3. `startup` 回归 <= `+10%`。

### 4.5 复算与审计要求

1. 任一层必须同时提交：执行命令、退出码、日志路径、JSON 产物路径。
2. 若为 `PASS-ENV-LIMITED`，必须记录缺失依赖或环境限制（例如 Go 二进制缺失、权限不足）。
3. 对外文档只允许引用 `reports/performance/l19/<run_id>/l19_perf_acceptance.json` 的数据，不允许手工抄写阈值结论。

---

## 5. 安全验收（Security Acceptance）

### 5.1 依赖安全

```bash
# 无 HIGH/CRITICAL 漏洞
cargo deny check advisories
# 预期：全部 PASS

# 许可证合规
cargo deny check licenses
# 预期：全部 PASS
```

### 5.2 密钥管理

| 检查项 | 验收标准 |
|--------|---------|
| 文件权限 | 密钥文件 0600 |
| 日志脱敏 | tokens/keys 自动 redact |
| TLS 版本 | 强制 TLS 1.2+ |

---

## 6. CI/CD 验收

### 6.1 CI 流水线检查

```yaml
# 必须通过的 CI 步骤：
- cargo fmt --check
- cargo clippy --workspace --all-features
- cargo test --workspace
- cargo deny check
- cargo build -p app --features parity --release
```

### 6.2 Parity 构建

```bash
# Parity 特性集验证
cargo build -p app --features "parity" --release

# 功能验证
./target/release/app version
./target/release/app check -c test_config.json
```

---

## 7. 验收流程

### 7.1 自动化验收

```bash
#!/bin/bash
# acceptance_check.sh

set -e

echo "=== 1. 依赖边界检查 ==="
./agents-only/06-scripts/check-boundaries.sh

echo "=== 2. 代码质量 ==="
cargo fmt --check
cargo clippy --workspace --all-features -- -D warnings

echo "=== 3. 测试通过 ==="
cargo test --workspace

echo "=== 4. 安全检查 ==="
cargo deny check

echo "=== 5. Parity 构建 ==="
cargo build -p app --features parity --release

echo "=== ✅ ALL PASSED ==="
```

### 7.2 手动验收清单

- [ ] 配置文件兼容性（与 Go sing-box 配置）
- [ ] 热重载功能（SIGHUP）
- [ ] 管理 API 响应
- [ ] 日志输出格式
- [ ] Prometheus metrics 导出

---

## 8. 验收记录模板

```markdown
## 验收记录

**日期**: YYYY-MM-DD
**验收人**: [Name]
**版本**: [Git SHA]

### 自动化检查
- [ ] 依赖边界: PASS-STRICT / PASS-ENV-LIMITED / FAIL
- [ ] 代码质量: PASS-STRICT / PASS-ENV-LIMITED / FAIL
- [ ] 测试覆盖: PASS-STRICT / PASS-ENV-LIMITED / FAIL (覆盖率 %)
- [ ] 安全检查: PASS-STRICT / PASS-ENV-LIMITED / FAIL
- [ ] Parity 构建: PASS-STRICT / PASS-ENV-LIMITED / FAIL

### 手动检查
- [ ] 配置兼容: PASS-STRICT / PASS-ENV-LIMITED / FAIL
- [ ] 热重载: PASS-STRICT / PASS-ENV-LIMITED / FAIL
- [ ] API: PASS-STRICT / PASS-ENV-LIMITED / FAIL
- [ ] 日志: PASS-STRICT / PASS-ENV-LIMITED / FAIL
- [ ] Metrics: PASS-STRICT / PASS-ENV-LIMITED / FAIL

### 备注
[任何特殊情况或已知问题]
[若为 PASS-ENV-LIMITED，必须写明环境限制与原始日志路径]

### 结论
□ 通过验收
□ 需要返工
```

---

*下一步：阅读 [03-ARCHITECTURE-SPEC.md](./03-ARCHITECTURE-SPEC.md) 了解架构规范*
