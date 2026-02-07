# 脚本工具定义（Tools Definition）

> **用途**：以函数定义形式描述可用脚本，便于 AI Agent 调用

---

## restore-context.sh ⚠️ DRP

| 属性 | 值 |
|------|-----|
| **目标** | 自动恢复损坏的 active_context.md |
| **用法** | `./06-scripts/restore-context.sh` |
| **输出** | 生成新的 active_context.md（并备份旧文件） |
| **使用场景** | 当 active_context.md 为空或损坏时（DRP 触发） |

---

## verify-consistency.sh ✅ 验证

| 属性 | 值 |
|------|-----|
| **目标** | 验证 active_context 与 workpackage 一致性 |
| **用法** | `./06-scripts/verify-consistency.sh` |
| **输出** | 一致性检查报告（通过/失败） |
| **使用场景** | init.md Step 2 验证战略一致性时 |

---

## analyze-deps.sh

| 属性 | 值 |
|------|-----|
| **目标** | 分析指定 crate 的依赖树 |
| **用法** | `./06-scripts/analyze-deps.sh <crate_name>` |
| **输出** | JSON 格式的依赖报告 |
| **使用场景** | 需要重构依赖或检查循环依赖时 |

---

## find-violations.sh

| 属性 | 值 |
|------|-----|
| **目标** | 查找违反依赖宪法的代码 |
| **用法** | `./06-scripts/find-violations.sh [crate]` |
| **输出** | 违规列表（文件:行号:违规类型） |
| **使用场景** | 重构前识别边界违规 |

---

## check-boundaries.sh

| 属性 | 值 |
|------|-----|
| **目标** | 验证 crate 边界是否符合架构规范 |
| **用法** | `./06-scripts/check-boundaries.sh` |
| **输出** | 通过/失败报告 |
| **使用场景** | 提交前验证架构约束 |

---

## 常用 Cargo 命令

| 命令 | 用途 | 使用场景 |
|------|------|---------|
| `cargo check` | 快速编译检查 | 修改后快速验证 |
| `cargo build` | 完整编译 | 准备运行测试 |
| `cargo test` | 运行测试 | 验证功能正确性 |
| `cargo clippy` | 代码质量检查 | 提交前检查 |
| `cargo tree -p <crate>` | 依赖树 | 分析依赖关系 |
| `cargo deny check` | 安全检查 | 验证依赖安全性 |

---

*最后更新：2026-02-07*
