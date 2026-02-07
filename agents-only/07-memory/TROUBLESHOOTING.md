# 故障排查手册（Troubleshooting）

> **用途**：记录遇到过的怪异报错及解决方案
> **维护者**：AI Agent 遇到问题解决后主动记录

---

## 编译错误

### 链接器错误

| 错误 | 原因 | 解决方案 |
|------|------|---------|
| `linker 'cc' not found` | macOS 缺少 Xcode CLI | `xcode-select --install` |
| `aws-lc-sys build failed` | 缺少 cmake/go | `brew install cmake go` |

### 依赖错误

| 错误 | 原因 | 解决方案 |
|------|------|---------|
| `duplicate lang item` | 重复引入 std | 检查 `#![no_std]` 配置 |
| `version solving failed` | 依赖版本冲突 | `cargo update -p <crate>` |

---

## 运行时错误

### 网络相关

| 错误 | 原因 | 解决方案 |
|------|------|---------|
| `Address already in use` | 端口被占用 | `lsof -i :<port>` 检查 |
| `Permission denied (TUN)` | 缺少权限 | macOS 需要 root 或授权 |

### 配置相关

| 错误 | 原因 | 解决方案 |
|------|------|---------|
| `unknown field` | 配置字段名错误 | 检查 YAML/JSON 结构 |
| `invalid type` | 类型不匹配 | 检查配置值类型 |

---

## 测试相关

| 问题 | 原因 | 解决方案 |
|------|------|---------|
| 测试相互干扰 | 全局状态 | 使用 `serial_test` |
| 端口冲突 | 并行测试 | 使用随机端口 `:0` |

---

## 项目特定问题

*（随开发进展补充）*

| 问题 | 原因 | 解决方案 | 添加日期 |
|------|------|---------|---------|
| - | - | - | - |

---

*最后更新：2026-02-07*
