# 00 - 重构目标与成功标准

## 目标一句话

> **让“边界”成为硬约束，让“复杂度”有归宿。**

本次 V2 不是“再拆更多模块”，而是把当前已经写在规范里的分层，落实为：
- **依赖方向不可逆**（核心永远不依赖外部适配）
- **协议实现与平台服务从 sb-core 迁出**
- **公共接口（Ports）明确到 trait 级别**
- **测试与性能剖析可分层进行**

---

## 成功标准（验收条款）

### A. 依赖树

- sb-core 的依赖不包含：`axum / tonic / tower / hyper / reqwest / rustls / quinn / tokio-tungstenite` 等控制面与传输面大库
- sb-types 不包含：tokio、网络库、TLS/QUIC/HTTP 库
- sb-api 不依赖 sb-adapters（控制面不能直接调用协议实现）

### B. 代码归属

- 所有 Outbound/Inbound 协议实现归属到 `sb-adapters`
- 所有平台/系统服务（NTP/systemd-resolved/DERP/SSM API 等）归属到 `sb-platform`（或其子 crate）
- sb-core 只保留：路由/策略/会话编排/调度/生命周期管理

### C. 可测试性

- sb-core 单元测试不需要启动真实网络栈即可跑通（通过 mock ports）
- 协议适配器可用 integration tests 单独测试（可用 `sb-test-utils` 提供的虚拟网络）

### D. 性能

- 热路径（路由决策、出站选择、DNS 缓存）不使用无节制的 `dyn async-trait`；优先 enum 静态分发
- 观测（metrics/tracing）不成为热路径上的同步瓶颈

---

## 非目标（本轮不强制）

- 立即切换到 Rust edition 2024
- 彻底推翻 workspace crate 命名
- 引入“真正的插件动态加载”（`cdylib`）——可以做预留，但不作为验收门槛
