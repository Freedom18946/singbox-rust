# Agents-Only 文档索引

> **AI 必读**：执行任何任务前，先完成 [init.md](./init.md) 检查清单。
> **AI 必遵**：严格遵守 [AI-RULES.md](./AI-RULES.md) 操作规则。

---

## 📁 目录结构

```
agents-only/
├── init.md                     # 🚨 AI 初始化检查（必读）
├── active_context.md           # ⚡ 当前状态快照（高频更新）
├── AI-RULES.md                 # 📜 AI 操作规则（必遵）
├── log.md                      # 📝 AI 行为日志（必写）
├── workpackage_latest.md       # 📋 当前工作包追踪
├── TBD.md                      # ❓ 待决定事项
├── README.md                   # 本文件
│
├── 00-overview/                # 概览
│   ├── 00-PROJECT-OVERVIEW.md
│   └── 05-USER-ABSTRACT-REQUIREMENTS.md
│
├── 01-spec/                    # 规范（权威定义）
│   ├── 01-REQUIREMENTS-ANALYSIS.md
│   ├── 02-ACCEPTANCE-CRITERIA.md
│   ├── 03-ARCHITECTURE-SPEC.md # 架构权威文档
│   └── REQUIREMENTS-CLARIFICATION.md
│
├── 02-reference/               # 参考资料
│   ├── 07-DEPENDENCY-AUDIT.md
│   ├── 08-PROJECT-STRUCTURE.md
│   ├── 09-GO-DESIGN-REFERENCE.md
│   ├── ARCHSPEC-ARCHIVE.md     # 旧 archspec 归档
│   ├── GLOSSARY.md             # 术语表
│   └── GO_PARITY_MATRIX.md
│
├── 03-planning/                # 规划
│   ├── 04-IMPLEMENTATION-GUIDE.md
│   └── 06-STRATEGIC-ROADMAP.md
│
├── 04-workflows/               # 工作流程（状态追踪）
│   ├── REFACTOR-PROGRESS.md
│   ├── CODE-MIGRATION.md
│   ├── BLOCKERS.md
│   ├── TEST-MAPPING.md
│   └── CRATE-DETAIL.md
│
├── 05-analysis/                # 分析结果
│   ├── CRATE-STRUCTURE.md
│   ├── VIOLATION-LOCATIONS.md
│   ├── DEPENDENCY-GRAPH.md
│   ├── FEATURE-FLAGS.md
│   └── PUBLIC-API.md
│
├── 06-scripts/                 # 辅助脚本
│   ├── TOOLS_DEF.md            # 脚本使用说明
│   ├── restore-context.sh      # DRP 恢复脚本
│   ├── verify-consistency.sh   # 一致性验证脚本
│   ├── analyze-deps.sh
│   ├── find-violations.sh
│   └── check-boundaries.sh
│
├── 07-memory/                  # 🧠 长期记忆
│   ├── LEARNED-PATTERNS.md     # 经验模式
│   └── TROUBLESHOOTING.md      # 故障排查
│
├── templates/                  # 📄 模板库
│   ├── TASK-REPORT.template.md
│   ├── ANALYSIS-RESULT.template.md
│   ├── MIGRATION-RECORD.template.md
│   └── DECISION.template.md
│
├── dump/                       # 🗑️ 临时文件（TTL=7天）
│   └── README.md
│
└── archive/                    # 📦 归档
    └── dump/                   # 过期 dump 文件
```

---

## 🚀 快速入口

| 场景 | 文档 |
|------|------|
| 新 AI 开始工作 | [init.md](./init.md) |
| 当前状态 | [active_context.md](./active_context.md) |
| 操作规则 | [AI-RULES.md](./AI-RULES.md) |
| 了解项目目标 | [00-overview/00-PROJECT-OVERVIEW.md](./00-overview/00-PROJECT-OVERVIEW.md) |
| 理解架构约束 | [01-spec/03-ARCHITECTURE-SPEC.md](./01-spec/03-ARCHITECTURE-SPEC.md) |
| 查看当前进度 | [workpackage_latest.md](./workpackage_latest.md) |
| 术语查询 | [02-reference/GLOSSARY.md](./02-reference/GLOSSARY.md) |
| 经验积累 | [07-memory/](./07-memory/) |
| 创建新文档 | [templates/README.md](./templates/README.md) |
| 存放临时输出 | [dump/README.md](./dump/README.md) |

---

## 📐 文档层次

```
┌─────────────────────────────────────────────────────────────┐
│  01-spec/                  权威定义（真相之源）              │
│  └── 03-ARCHITECTURE-SPEC  架构/职责边界的权威文档           │
└─────────────────────────────────────────────────────────────┘
                               ↓
┌─────────────────────────────────────────────────────────────┐
│  04-workflows/             状态追踪（引用 01-spec）          │
│  └── CRATE-DETAIL          → 链接到 ARCHITECTURE-SPEC       │
└─────────────────────────────────────────────────────────────┘
                               ↓
┌─────────────────────────────────────────────────────────────┐
│  07-memory/                长期记忆（经验积累）              │
│  └── LEARNED-PATTERNS      模式 / TROUBLESHOOTING 故障      │
└─────────────────────────────────────────────────────────────┘
                               ↓
┌─────────────────────────────────────────────────────────────┐
│  dump/                     临时输出（可清理，TTL=7天）       │
│  └── YYYY-MM-DD-*.md       → 过期后移动到 archive/dump/     │
└─────────────────────────────────────────────────────────────┘
```

---

*更新时间: 2026-02-07*
