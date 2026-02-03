# 迁移计划（Step-by-step）

> 原则：先“立法”再“迁都”。没有边界门禁的迁移 = 必然回流。

---

## Phase 0：立法（必须先做）

- 落地依赖边界检查（CI）
- 建立 crate 宪法
- 冻结新增越界依赖

验收：
- 任意新 PR 不能增加 sb-core 对 Web/TLS/QUIC 的依赖

---

## Phase 1：迁出 outbound/inbound 协议实现

- 将 `sb-core/src/outbound/*` 移至 `sb-adapters/src/outbound/*`
- 将 `sb-core/src/inbound/*`（如存在协议实现）移至 `sb-adapters/src/inbound/*`
- sb-core 只保留 Outbound 选择与调度（registry/health）

验收：
- sb-core 不再包含任何协议握手/加密代码

---

## Phase 2：迁出 platform/services

- 将 `sb-core/src/services/*` 迁到 `sb-platform/src/...`
- 对外以 Ports 形式提供（DnsPort/TimePort/DerpPort 等）

验收：
- sb-core 不再出现 systemd-resolved/NTP/DERP 等实现

---

## Phase 3：控制面与数据面解耦

- sb-core 暴露 `AdminPort/StatsPort`（或通过 sb-types 定义）
- sb-api 注入 Ports，移除对 sb-core router feature 的硬依赖

验收：
- sb-api 不再依赖 sb-adapters
- sb-core 不再依赖 axum/tonic/tower/hyper
