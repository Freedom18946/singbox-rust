# 目录索引（Documentation Index）

> **agents-only 文档结构总览**：快速导航到所需信息。

---

## 🚨 AI 必读入口

**首次进入必须执行**：[init.md](./init.md) - 初始化检查清单

**行为记录必须更新**：[log.md](./log.md) - AI 行为日志

---

## 📚 文档结构

```
agents-only/
├── init.md                         # 🚨 AI 初始化检查（必读）
├── log.md                          # 📝 AI 行为日志（必写）
├── README.md                       # 本文件
├── 00-PROJECT-OVERVIEW.md          # 项目概览
├── 01-REQUIREMENTS-ANALYSIS.md     # 需求分析
├── 02-ACCEPTANCE-CRITERIA.md       # 验收标准
├── 03-ARCHITECTURE-SPEC.md         # 架构规范
├── 04-IMPLEMENTATION-GUIDE.md      # 实现指南
├── 05-USER-ABSTRACT-REQUIREMENTS.md # 用户抽象需求
├── 06-STRATEGIC-ROADMAP.md         # 战略路线图
└── 07-DEPENDENCY-AUDIT.md          # 依赖边界审计
```

---

## 🎯 按场景查阅

### 我需要了解项目整体情况
→ 阅读 [00-PROJECT-OVERVIEW.md](./00-PROJECT-OVERVIEW.md)

### 我需要了解要实现什么功能
→ 阅读 [01-REQUIREMENTS-ANALYSIS.md](./01-REQUIREMENTS-ANALYSIS.md)

### 我需要知道如何验收工作
→ 阅读 [02-ACCEPTANCE-CRITERIA.md](./02-ACCEPTANCE-CRITERIA.md)

### 我需要理解架构设计
→ 阅读 [03-ARCHITECTURE-SPEC.md](./03-ARCHITECTURE-SPEC.md)

### 我需要开始写代码
→ 阅读 [04-IMPLEMENTATION-GUIDE.md](./04-IMPLEMENTATION-GUIDE.md)

---

## 🔑 关键信息速查

### 当前状态
- **Parity**: 88% (183/209)
- **Baseline**: sing-box Go 1.12.14
- **Rust**: 1.92+

### 核心约束
1. **依赖单向**：sb-types ← sb-core ← sb-adapters
2. **sb-core 纯净**：无协议实现、无平台服务、无 Web 框架
3. **Features 聚合**：只在 app 聚合 features

### 验证命令
```bash
# 构建 parity
cargo build -p app --features parity --release

# 完整检查
cargo fmt --check && cargo clippy --workspace && cargo test --workspace && cargo deny check
```

---

## 📖 原始文档索引

### 根目录关键文档
| 文档 | 用途 |
|------|------|
| `README.md` | 项目入口 |
| `NEXT_STEPS.md` | 当前里程碑 |
| `PROJECT_STRUCTURE_NAVIGATION.md` | 目录结构（唯一真相） |
| `GO_PARITY_MATRIX.md` | Go 对齐状态（538 行详细对比） |
| `SECURITY.md` | 安全策略 |
| `TEST_COVERAGE.md` | 测试覆盖 |
| `USAGE.md` | CLI 用法 |

### singbox_archspec_v2 结构
| 目录 | 内容 |
|------|------|
| `00-goals/` | 目标和术语表 |
| `01-constitution/` | 依赖宪法、错误模型、测试策略等 |
| `02-architecture/` | 总体架构、数据面、控制面 |
| `03-crates/` | 逐 crate 规范 |
| `04-interfaces/` | Ports 和接口契约 |
| `05-reference/` | 依赖矩阵 |
| `06-implementation-guides/` | 配置编译、模糊测试、日志等 |
| `07-migration/` | 迁移计划 |
| `08-refactor-tracking/` | 重构追踪日志 |
| `templates/` | 代码模板 |

> **注意**：singbox_archspec_v2 作为**深度参考**保留，日常开发以 agents-only 为准。
> 需要详细 crate 规范或接口定义时再查阅 archspec。

---

## ✅ 快速验收检查表

```bash
# 1. 依赖边界
! cargo tree -p sb-core | grep -qE "axum|tonic|tower|hyper|rustls|quinn"

# 2. 代码质量
cargo fmt --check
cargo clippy --workspace --all-features -- -D warnings

# 3. 测试
cargo test --workspace

# 4. 安全
cargo deny check

# 5. 构建
cargo build -p app --features parity --release
```

---

*本文档由 AI 整合生成，基于项目根目录和 singbox_archspec_v2 的文档。*
*生成时间: 2026-02-07*
