# L4 质量复验报告（2026-02-10）

## 1. 范围

本报告用于固化 L4.5 的最小复验命令链，并按双轨口径给出结论：

- `PASS-STRICT`
- `PASS-ENV-LIMITED`
- `FAIL`

命令集（固定）：
- `./scripts/test_feature_gates.sh`
- `./scripts/test/acceptance/schema-v2.sh`
- `./scripts/test/bench/run.sh`
- `./scripts/test/stress/run.sh short`

日志目录：`/tmp/l4_quality_logs_20260210/`

---

## 2. 执行结果

| 命令 | 结果 | 口径 | 证据 |
|------|------|------|------|
| `./scripts/test_feature_gates.sh` | 通过 | `PASS-STRICT` | `/tmp/l4_quality_logs_20260210/01_feature_gates.log` |
| `./scripts/test/acceptance/schema-v2.sh` | 通过（含 1 项功能性 SKIP） | `PASS-ENV-LIMITED` | `/tmp/l4_quality_logs_20260210/02_schema_v2.log` |
| `./scripts/test/bench/run.sh` | 通过（生成 `target/bench/summary.csv`） | `PASS-STRICT` | `/tmp/l4_quality_logs_20260210/03_bench_run.log` |
| `./scripts/test/stress/run.sh short` | 脚本通过（压力 case 因权限受限被标记 SKIP） | `PASS-ENV-LIMITED` | `/tmp/l4_quality_logs_20260210/04_stress_short.log` |

---

## 3. 关键观察

1. `feature_gates` 链路可运行，含 warning 但不阻断。
2. `schema-v2` 的 `allow-unknown` 行为在当前 binary 未支持，脚本按 SKIP 处理。
3. `bench/run.sh` 可完整执行并输出基准汇总，日志中存在“regressed”信号，需在后续 guard 阶段判定是否超阈值。
4. `stress short` 在当前主机受 socket 权限限制，测试体 panic 后被脚本识别为环境阻塞并降级为 SKIP。

---

## 4. 结论

- 本轮质量复验整体结论：`PASS-ENV-LIMITED`。
- 若需升级为 `PASS-STRICT`，至少需要：
  - 在非受限环境完成 `stress short`（无 PermissionDenied SKIP）；
  - 对 `schema-v2` 的 SKIP 项进行功能确认或在验收口径中明确该项非阻塞。

---

## 5. 关联产物

- 压测日志：`reports/stress-tests/stress_test_short_20260210_193539.log`
- 压测汇总：`reports/stress-tests/summary_20260210_193539.txt`
- 基准汇总：`target/bench/summary.csv`
