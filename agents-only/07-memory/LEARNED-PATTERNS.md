# 经验模式库（Learned Patterns）

> **用途**：记录项目中特殊的代码模式、约定和最佳实践
> **维护者**：AI Agent 在开发过程中主动更新

---

## 错误处理

| 模式 | 说明 | 示例 |
|------|------|------|
| 使用 `thiserror` | 所有公共 crate 错误类型 | `#[derive(thiserror::Error)]` |
| 避免 `.unwrap()` | 核心逻辑禁用，测试代码可用 | 用 `?` 或 `anyhow::Context` |
| 错误链保留 | 使用 `#[from]` 或 `#[source]` | 保留原始错误信息 |

---

## 异步模式

| 模式 | 说明 |
|------|------|
| `tokio::select!` | 多路复用时优先使用 |
| 避免 `async-trait` 热路径 | 使用 enum dispatch 替代 |
| `CancellationToken` | 优雅关闭使用 tokio_util |

---

## 依赖边界

| 规则 | 详情 |
|------|------|
| sb-types 零大依赖 | 禁止 tokio/hyper/axum |
| sb-core 无协议实现 | 协议只在 sb-adapters |
| 控制面隔离 | sb-api 不能把 axum 带入 sb-core |

---

## 项目特定约定

*（随开发进展补充）*

| 约定 | 原因 | 添加日期 |
|------|------|---------|
| - | - | - |

---

*最后更新：2026-02-07*
