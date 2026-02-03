# 迁移：现状 vs 目标（问题对照表）

## 现状痛点（来自代码归属/依赖树）

- sb-core 内含大量协议实现：`src/outbound/*`
- sb-core 内含大量平台服务：`src/services/*`
- sb-core 依赖 Web/TLS/WS 大库，导致编译慢、边界混乱
- sb-api 通过 feature 直接拉起 sb-core/router 等，控制面与数据面耦合

## 目标状态

- 协议实现全部迁到 sb-adapters
- 平台服务全部迁到 sb-platform
- sb-core 只做编排与策略
- sb-api 只依赖 sb-core 的 Admin/Stats 端口
