# 项目结构导航（Project Structure Navigation）

> 本文件是项目结构的权威导航入口。  
> 目标不是罗列每个文件，而是给出在维护模式下仍然稳定、可依赖的目录与入口。

## 当前仓库形态

- 仓库状态：L1-L25 已关闭，当前为 maintenance mode
- `.github/` 目录仍存在，但 workflow automation 已永久停用；不能再把 workflow 文件或 CI 叙事当作当前结构的一部分
- 根 `GO_PARITY_MATRIX.md` 是跳转入口；权威正文在 `agents-only/reference/GO_PARITY_MATRIX.md`

## 顶层目录（当前有效）

```text
singbox-rust/
├── agents-only/         # AI/agent 专用参考、上下文、阶段地图
├── app/                 # CLI、组合根、运行入口
├── benches/             # 基准工作区
├── benchmark_results/   # 已跟踪基准输出摘要
├── configs/             # 配置与测试配置
├── crates/              # 主要 crate 工作区
├── deployment/          # 部署脚本与配置
├── deployments/         # 部署示例
├── docs/                # 用户/开发/运维文档
├── examples/            # 示例与样例配置
├── fuzz/                # fuzz 相关内容
├── go_fork_source/      # Go 参考实现
├── grafana/             # 监控看板
├── labs/                # interop lab / dual-kernel 资料
├── LICENSES/            # 依赖许可证
├── reports/             # 历史报告、阶段证据、运行产物索引
├── scripts/             # 本地验证与工具脚本
├── tests/               # 仓库级测试
├── tools/               # 内部工具
├── vendor/              # 第三方覆写
├── xtask/               # 开发辅助任务
├── xtests/              # 扩展测试工具
├── README.md            # 项目入口说明
├── GO_PARITY_MATRIX.md  # redirect entry
├── Cargo.toml           # workspace manifest
└── SECURITY.md          # 安全说明
```

## 关键工作区目录

### `crates/`

当前主要 crate：

- `sb-core`
- `sb-adapters`
- `sb-config`
- `sb-types`
- `sb-transport`
- `sb-tls`
- `sb-platform`
- `sb-api`
- `sb-runtime`
- `sb-metrics`
- `sb-security`
- `sb-common`
- `sb-proto`
- `sb-subscribe`
- `sb-admin-contract`
- `sb-test-utils`

结构口径说明：

- `sb-core` 采用“内核合集层”定义，详见 `ARCHITECTURE-SPEC.md`
- 新协议默认归属 `sb-adapters`
- 实际边界以 `check-boundaries.sh` 和 `boundary-policy.json` 为准

### `app/`

- `app/src/bin/`：命令入口
- `app/src/cli/`：命令实现与共享 CLI 逻辑
- `app/src/bootstrap.rs`、`app/src/run_engine.rs`：运行装配/共享运行逻辑
- `app/tests/`：app 级集成与 e2e 测试

### `docs/`

稳定分区：

- `00-getting-started/`
- `01-user-guide/`
- `02-cli-reference/`
- `03-operations/`
- `04-development/`
- `05-api-reference/`
- `06-advanced-topics/`
- `07-reference/`
- `08-examples/`
- `archive/`

重点文件：

- `docs/STATUS.md`
- `docs/capabilities.md`
- `docs/MIGRATION_GUIDE.md`
- `docs/TLS_DECISION.md`

### `reports/`

`reports/` 不是当前项目状态的唯一真相来源。它当前包含三类内容：

- 当前仍会被读取的摘要文件，如 `capabilities.json`、`feature_matrix_report.txt`
- 历史快照文档，如 `VERIFICATION_RECORD.md`、`PERFORMANCE_REPORT.md`
- 已跟踪运行产物与 phase 证据目录，如 `l18/`、`l21/artifacts/`、`benchmarks/criterion_data/`

使用前先读 `reports/README.md`。

### `agents-only/`

当前最重要的入口：

- `agents-only/active_context.md`
- `agents-only/workpackage_latest.md`
- `agents-only/reference/ARCHITECTURE-SPEC.md`
- `agents-only/reference/ACCEPTANCE-CRITERIA.md`
- `agents-only/reference/GO_PARITY_MATRIX.md`

## 常用权威文档

| 主题 | 当前入口 |
|------|------|
| 双内核 parity / oracle 口径 | `labs/interop-lab/docs/dual_kernel_golden_spec.md` |
| 当前上下文 | `agents-only/active_context.md` |
| 阶段总览 / phase map | `agents-only/workpackage_latest.md` |
| 架构边界 | `agents-only/reference/ARCHITECTURE-SPEC.md` |
| 验收口径 | `agents-only/reference/ACCEPTANCE-CRITERIA.md` |
| Closure / parity 矩阵 | `agents-only/reference/GO_PARITY_MATRIX.md` |
| capability ledger 说明 | `docs/capabilities.md` |
| 历史报告入口 | `reports/README.md` |

## 维护模式下的导航规则

- 不要再引用已删除或已失效的入口，如 `NEXT_STEPS.md`、`agents-only/planning/L18-PHASE4.md`、`.gitmodules`、`CHANGELOG.md`
- 根 `GO_PARITY_MATRIX.md` 仅作跳转，不承担正文维护
- 目录树应只记录稳定入口，不记录高漂移的细节文件清单
- 若结构发生变化，优先同步本文件和相关入口 README，而不是继续复制粘贴旧树

## 结构核对清单

- [ ] 顶层目录仍与本文件一致
- [ ] `crates/` 关键 crate 列表仍有效
- [ ] `reports/` 分类说明与 `reports/README.md` 一致
- [ ] 所有“权威入口”路径都存在
- [ ] 不再引用已删除的旧阶段文件

---

*最后更新：2026-03-21*
