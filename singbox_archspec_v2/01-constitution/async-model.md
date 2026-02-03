# Async 模型与分发策略（Async & Dispatch）

## 1) 为什么要写这份规则

当前工程大量使用 `async-trait`。它解决了 `dyn Trait + async` 的工程痛点，但会带来：
- 额外 boxing/动态分发开销
- trait 方法签名隐藏，难以推断生命周期与 Send 边界
- 热路径上可能放大成本

本规范提供一个“选择树”，coding agent 必须按它选型，避免随意扩散 `async-trait`。

---

## 2) 选择树（硬规则）

### A. 热路径（每连接/每包）优先：**enum 静态分发**

适用：Outbound 选择、Inbound handler、DNS resolver（高频）。

做法：
- 把运行时“协议类型”收敛为 enum：
  - `enum Outbound { Direct(Direct), Vmess(Vmess), ... }`
- 对外暴露统一方法：
  - `async fn connect(&self, ctx: &ConnCtx) -> Result<Stream, CoreError>`

### B. 非热路径/扩展点：允许 `dyn Trait`，但成本关在边界

适用：管理接口、订阅更新、少量后台服务。

做法：
- 内部 trait 使用 `async fn`（便于实现）
- 对外的 object-safe 接口使用 wrapper：
  - `fn call(&self) -> Pin<Box<dyn Future<Output = ...> + Send + '_>>`

### C. 仅在必须时使用 `async-trait`

适用：需要 object-safe 且实现者众多且短期难改。

规则：
- 仅限 `sb-adapters`、`sb-platform`、`sb-transport`
- 禁止在 `sb-core` 使用 `async-trait`（除非明确标记为非热路径，并在文档说明原因）

---

## 3) Send/Sync 规则

- 数据面所有 future 默认 `Send`（便于多线程 runtime）
- 只有在明确是单线程场景（例如 wasm 或特定嵌入）才允许 `!Send`，必须用 feature gate 标注
