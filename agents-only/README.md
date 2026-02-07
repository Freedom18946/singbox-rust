# Agents-Only 文档索引

> **AI 必读**：执行任何任务前，先完成 [init.md](./init.md) 检查清单。
> **AI 必写**：完成任务后，更新 [log.md](./log.md) 日志。

---

## 📁 目录结构

```
agents-only/
├── init.md                     # 🚨 AI 初始化检查（必读）
├── log.md                      # 📝 AI 行为日志（必写）
├── workpackage_latest.md       # 📋 当前工作包追踪
├── README.md                   # 本文件
│
├── 00-overview/                # 概览
│   ├── PROJECT-OVERVIEW.md
│   └── USER-ABSTRACT-REQUIREMENTS.md
│
├── 01-spec/                    # 规范（权威定义）
│   ├── REQUIREMENTS-ANALYSIS.md
│   ├── REQUIREMENTS-CLARIFICATION.md  # 需求澄清
│   ├── ACCEPTANCE-CRITERIA.md
│   └── ARCHITECTURE-SPEC.md    # 架构权威文档
│
├── 02-reference/               # 参考资料
│   ├── DEPENDENCY-AUDIT.md
│   ├── PROJECT-STRUCTURE.md
│   └── GO-DESIGN-REFERENCE.md
│
├── 03-planning/                # 规划
│   ├── STRATEGIC-ROADMAP.md
│   └── IMPLEMENTATION-GUIDE.md
│
├── 04-workflows/               # 工作流程（状态追踪）
│   ├── REFACTOR-PROGRESS.md
│   ├── CODE-MIGRATION.md
│   ├── BLOCKERS.md
│   ├── TEST-MAPPING.md
│   └── CRATE-DETAIL.md         # → 链接到 01-spec/ARCHITECTURE-SPEC
│
├── 05-analysis/                # 分析结果
│   ├── CRATE-STRUCTURE.md
│   ├── VIOLATION-LOCATIONS.md
│   ├── DEPENDENCY-GRAPH.md
│   ├── FEATURE-FLAGS.md
│   └── PUBLIC-API.md
│
├── 06-scripts/                 # 辅助脚本
│   ├── analyze-deps.sh
│   ├── find-violations.sh
│   └── check-boundaries.sh
│
├── templates/                  # 🆕 模板库
│   ├── TASK-REPORT.template.md
│   ├── ANALYSIS-RESULT.template.md
│   ├── MIGRATION-RECORD.template.md
│   └── DECISION.template.md
│
└── dump/                       # 🆕 临时文件
    └── README.md               # 存放一次性生成的文档
```

---

## 🚀 快速入口

| 场景 | 文档 |
|------|------|
| 新 AI 开始工作 | [init.md](./init.md) |
| 了解项目目标 | [00-overview/PROJECT-OVERVIEW.md](./00-overview/00-PROJECT-OVERVIEW.md) |
| 理解架构约束 | [01-spec/ARCHITECTURE-SPEC.md](./01-spec/03-ARCHITECTURE-SPEC.md) |
| 查看当前进度 | [workpackage_latest.md](./workpackage_latest.md) |
| 开始重构任务 | [04-workflows/REFACTOR-PROGRESS.md](./04-workflows/REFACTOR-PROGRESS.md) |
| 创建新文档 | [templates/README.md](./templates/README.md) |
| 存放临时输出 | [dump/README.md](./dump/README.md) |

---

## 📐 文档层次

```
┌─────────────────────────────────────────────────────────────┐
│  01-spec/                  权威定义（真相之源）              │
│  ├── ARCHITECTURE-SPEC     架构/职责边界的权威文档           │
│  └── REQUIREMENTS-*        需求的权威文档                   │
└─────────────────────────────────────────────────────────────┘
                               ↓
┌─────────────────────────────────────────────────────────────┐
│  04-workflows/             状态追踪（引用 01-spec）          │
│  ├── REFACTOR-PROGRESS     进度追踪                         │
│  └── CRATE-DETAIL          → 链接到 ARCHITECTURE-SPEC       │
└─────────────────────────────────────────────────────────────┘
                               ↓
┌─────────────────────────────────────────────────────────────┐
│  dump/                     临时输出（可清理）                │
│  └── YYYY-MM-DD-*.md       一次性报告                       │
└─────────────────────────────────────────────────────────────┘
```

**原则**：避免内容重复，使用链接引用权威文档。

---

*更新时间: 2026-02-07*
