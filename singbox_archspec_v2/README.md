# singbox-rust 架构重构规范（V2）

> 目标：把“纸面分层”变成“代码铁律”，并满足 Rust 工程化的长期可维护性/可演进性/可测试性要求。  
> 适用范围：本仓库 `singbox-rust`（workspace 结构不强制大改，但 **crate 边界、依赖方向、公共接口**必须按本文档执行）。  
> 版本基线：Rust **1.92**（与现有规范一致）  
> 文档生成日期：2026-02-02

---

## 你该从哪读起

1. **00-目标与原则**：本次重构“为什么这么切”、哪些是不可破坏的原则。
2. **01-依赖宪法与边界**：每个 crate 能做什么、不能做什么（CI 强制）。
3. **02-总体架构**：数据面/控制面的职责与交互。
4. **03-crates/**：逐个 crate 的“工程合同”（coding agent 以此落地，不会误解）。
5. **04-interfaces/**：核心 Ports（trait）与数据结构的“唯一真相”。
6. **07-migration/**：从当前代码迁移到目标架构的分步计划与映射表。

---

## 本文档的“硬约束”

- **依赖方向只能单向**：见 `01-constitution/dependency-constitution.md`。
- **sb-core 只做引擎，不做协议实现、不做平台服务**：协议实现只在 `sb-adapters`；平台服务只在 `sb-platform`。
- **sb-types 是契约层**：只放 Ports 与领域类型；不允许引入网络/HTTP/TLS/QUIC 等重量依赖。
- **控制面（sb-api）与数据面（sb-core/sb-adapters）隔离**：控制面永远不把 Web 框架依赖带入核心数据面。
- **特性（features）聚合在 app**：除 infra crate（transport/tls/security）外，其余 crate 禁止把 feature 当“隐式依赖开关”。

---

## 文件结构（本规范包）

- `00-goals/`：目标、原则、术语表
- `01-constitution/`：依赖宪法、错误模型、async 模型、feature 策略、测试策略
- `02-architecture/`：总体架构（数据面/控制面/配置编译/可观测性）
- `03-crates/`：逐 crate 规范（职责、边界、API、模块树、依赖）
- `04-interfaces/`：Ports 与接口契约（traits + 数据结构）
- `07-migration/`：迁移计划、映射表、阶段性验收标准
- `templates/`：可复制粘贴的 crate/trait/enum 分发模板

---

## 如何把它变成 CI 约束

- 依赖白名单检查：见 `01-constitution/ci-enforcement.md`
- clippy/deny/rustfmt/taplo：见 `01-constitution/toolchain-policy.md`
