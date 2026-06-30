<!-- tier: A -->
# Agents-Only 文档索引

> **AI 必读**：执行任何任务前，先完成 [init.md](./init.md) 检查清单。
> **AI 必遵**：稳定约定与硬规则见仓库根 [CLAUDE.md](../CLAUDE.md) + [AGENTS.md](../AGENTS.md)；
> 操作规则 [archive/README.md](./archive/README.md)（C-tier）。
> **当前阶段**：L1-L25 + 全部 MT-* 维护/验收线已关闭；MT-REAL-02 REALITY 本地主线已封箱
> （T3 收口）。当前状态与下一步以 `active_context.md` 为准（唯一权威）。

---

## 📁 当前目录结构（2026-06 重构后）

```
agents-only/
├── active_context.md            # S: 当前状态唯一权威（易变状态只在这里）
├── workpackage_latest.md        # S: 阶段地图 / 全局位置
├── init.md                      # S: 启动检查清单
├── README.md                    # 本索引
├── log.md                       # C: 终极流水帐（勿主动读）
├── mt_real_02_baseline.md       # REALITY ClientHello 基线长报告（已封箱，历史参考）
├── mt_real_02_fresh_sample_intake.md   # REALITY 历史 intake（已封箱）
├── mt_mixed_fresh_intake.md     # 前沿邻接（被 baseline 引用）
├── mt_trojan_fresh_sample_intake.md    # 被 trojan.rs 源码引用
├── mt_real_02_evidence/         # 前沿轮次证据
├── post1313/                    # B: Go 1.13.13 / GUI 1.25.1 差异分析与任务包规划
├── reference/                   # A: 权威参考（含 Rust_spec_v2.md）
├── memory/                      # A: 经验 + C: implementation-history
├── 06-scripts/                  # 本地治理/一致性辅助脚本
├── templates/                   # 文档模板
└── archive/                     # C: 强压缩历史归档（summary-only）
```

---

## 🚀 快速入口

| 场景 | 文档 |
|------|------|
| 新 AI 开始工作 | [init.md](./init.md) |
| **当前状态（唯一权威）** | [active_context.md](./active_context.md) |
| 阶段总览 / 全局位置 | [workpackage_latest.md](./workpackage_latest.md) |
| Go 1.13.13 / GUI 1.25.1 后续差异规划 | [post1313/README.md](./post1313/README.md) |
| REALITY 基线长报告（已封箱，历史参考） | [mt_real_02_baseline.md](./mt_real_02_baseline.md) |
| 发布前清理归档摘要 | [archive/release_cleanup_2026_06_summary.md](./archive/release_cleanup_2026_06_summary.md) |
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
| 审计结论（已压缩归档） | [archive/mt_summary.md](./archive/mt_summary.md) |
| 历史归档 | [archive/](./archive/) |

---

*更新时间: 2026-06-30*
