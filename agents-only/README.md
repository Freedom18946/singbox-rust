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
│   ├── PROJECT-OVERVIEW.md     # 项目概览
│   └── USER-ABSTRACT-REQUIREMENTS.md  # 用户抽象需求
│
├── 01-spec/                    # 规范
│   ├── REQUIREMENTS-ANALYSIS.md    # 需求分析
│   ├── ACCEPTANCE-CRITERIA.md      # 验收标准
│   └── ARCHITECTURE-SPEC.md        # 架构规范
│
├── 02-reference/               # 参考
│   ├── DEPENDENCY-AUDIT.md     # 依赖边界审计
│   ├── PROJECT-STRUCTURE.md    # 项目结构导航
│   └── GO-DESIGN-REFERENCE.md  # Go 设计参考
│
├── 03-planning/                # 规划
│   ├── STRATEGIC-ROADMAP.md    # 战略路线图
│   └── IMPLEMENTATION-GUIDE.md # 实现指南
│
├── 04-workflows/               # 工作流程
│   ├── README.md               # 工作流索引
│   ├── REFACTOR-PROGRESS.md    # 重构进度追踪
│   ├── CODE-MIGRATION.md       # 代码迁移日志
│   ├── BLOCKERS.md             # 阻塞项清单
│   ├── TEST-MAPPING.md         # 测试映射
│   └── CRATE-DETAIL.md         # Crate 详细职责
│
├── 05-analysis/                # 源码分析
│   ├── README.md               # 分析索引
│   ├── CRATE-STRUCTURE.md      # Crate 结构分析
│   ├── VIOLATION-LOCATIONS.md  # 违规代码位置
│   ├── DEPENDENCY-GRAPH.md     # 依赖关系图
│   ├── FEATURE-FLAGS.md        # Feature flag 分析
│   └── PUBLIC-API.md           # 公共 API 清单
│
└── 06-scripts/                 # 辅助脚本
    ├── README.md               # 脚本索引
    ├── analyze-deps.sh         # 依赖分析
    ├── find-violations.sh      # 查找违规
    └── check-boundaries.sh     # CI 边界检查
```

---

## 🚀 快速入口

| 场景 | 文档 |
|------|------|
| 新 AI 开始工作 | [init.md](./init.md) |
| 了解项目目标 | [00-overview/PROJECT-OVERVIEW.md](./00-overview/PROJECT-OVERVIEW.md) |
| 理解架构约束 | [01-spec/ARCHITECTURE-SPEC.md](./01-spec/ARCHITECTURE-SPEC.md) |
| 查看当前进度 | [workpackage_latest.md](./workpackage_latest.md) |
| 开始重构任务 | [04-workflows/REFACTOR-PROGRESS.md](./04-workflows/REFACTOR-PROGRESS.md) |
| 运行分析脚本 | [06-scripts/README.md](./06-scripts/README.md) |

---

## 🔗 深度参考

| 资料 | 位置 |
|------|------|
| Go 源码 | `go_fork_source/sing-box-1.12.14/` |
| GUI 源码 | `GUI_fork_source/GUI.for.SingBox-1.19.0/` |
| 详细 crate 规范 | `singbox_archspec_v2/03-crates/` |
| 接口定义 | `singbox_archspec_v2/04-interfaces/` |

---

*本文档由 AI 整合生成，是 AI 工作的入口点。*
*更新时间: 2026-02-07*
