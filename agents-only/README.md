<!-- tier: A -->
# Agents-Only 文档索引

> **AI 必读**：执行任何任务前，先完成 [init.md](./init.md) 检查清单。
> **AI 必遵**：稳定约定与硬规则见仓库根 [CLAUDE.md](../CLAUDE.md) + [AGENTS.md](../AGENTS.md)；
> 操作规则 [archive/README.md](./archive/README.md)（C-tier）。
> **当前阶段**：一律以 `active_context.md` 为准（唯一权威），本索引不复述阶段状态。

---

## 📁 当前目录结构（2026-07 压缩后）

```
agents-only/
├── active_context.md            # S: 当前状态唯一权威（易变状态只在这里，≤300行）
├── workpackage_latest.md        # S: 阶段地图 / 全局位置（≤120行）
├── init.md                      # S: 启动检查清单
├── README.md                    # 本索引
├── log.md                       # C: 终极流水帐（勿主动读；旧段在 archive/logs/）
├── post1313/                    # 活动轨迹：Go 1.13.13 / GUI 1.25.1 差异任务包
├── fable5审计报告/               # B: 2026-06 审计快照 + post_fable_packages（有处置决定，勿移动）
├── mt_real_01_evidence/         # 封箱证据（scripts/tools 测试硬编码路径，勿移动）
├── mt_real_02_evidence/         # 封箱证据（scripts/tools 测试硬编码路径，勿移动）
├── reference/                   # A: 权威参考（含 Rust_spec_v2.md）
├── memory/                      # A: 经验（LEARNED-PATTERNS / TROUBLESHOOTING / workflow_notes）+ C: implementation-history
├── 06-scripts/                  # 本地治理/一致性辅助脚本
├── templates/                   # 文档模板
└── archive/                     # C: 强压缩历史归档（含 lnx_rt_01，勿主动加载）
```

> 顶层只允许上述文件/目录。新工作产物落轨迹目录（如 `mig03/`），
> 轨迹关闭后 `git mv` 进 `archive/{track}/` —— `verify-consistency.sh` 会硬检查。

---

## 🚀 快速入口

| 场景 | 文档 |
|------|------|
| 新 AI 开始工作 | [init.md](./init.md) |
| **当前状态（唯一权威）** | [active_context.md](./active_context.md) |
| 阶段总览 / 全局位置 | [workpackage_latest.md](./workpackage_latest.md) |
| MIG-03 架构去重迁移 | [archive/mig03/README.md](./archive/mig03/README.md) |
| Go 1.13.13 / GUI 1.25.1 后续差异规划 | [post1313/README.md](./post1313/README.md) |
| Linux 运行时双核验证（已关闭） | [archive/lnx_rt_01/README.md](./archive/lnx_rt_01/README.md) |
| 稳定约定 / 硬规则 | [../CLAUDE.md](../CLAUDE.md)、[../AGENTS.md](../AGENTS.md) |
| 后续开发准则 | [reference/AGENT-DEVELOPMENT-GUIDELINES.md](./reference/AGENT-DEVELOPMENT-GUIDELINES.md) |
| Rust 规则原文 | [reference/Rust_spec_v2.md](./reference/Rust_spec_v2.md) |
| 架构约束 | [reference/ARCHITECTURE-SPEC.md](./reference/ARCHITECTURE-SPEC.md) |
| 验收口径 | [reference/ACCEPTANCE-CRITERIA.md](./reference/ACCEPTANCE-CRITERIA.md) |
| 脚本入口 | [reference/SCRIPTS-MAP.md](./reference/SCRIPTS-MAP.md) |
| Parity 矩阵（验收基线） | [reference/GO_PARITY_MATRIX.md](./reference/GO_PARITY_MATRIX.md) |
| 术语查询 | [reference/GLOSSARY.md](./reference/GLOSSARY.md) |
| 经验积累 | [memory/](./memory/) |
| 创建新文档 | [templates/README.md](./templates/README.md) |
| REALITY 基线长报告（已封箱） | [archive/mt_real_02/mt_real_02_baseline.md](./archive/mt_real_02/mt_real_02_baseline.md) |
| 历史归档（含 REALITY active-probing、审计、发布清理摘要） | [archive/](./archive/) |

---

*更新时间: 2026-07-18*
