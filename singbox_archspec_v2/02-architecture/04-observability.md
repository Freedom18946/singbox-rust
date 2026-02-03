# 可观测性（Tracing/Metrics/Logs）

## 总原则

- 数据面：tracing 是事件流，metrics 是聚合
- 控制面：日志优先，必要时暴露 trace 开关

---

## tracing

- 统一使用 `tracing`，span 命名规范：
  - `inbound.accept`, `engine.route`, `outbound.connect`, `relay.copy`
- Session 相关字段作为 span fields：
  - `sid`, `inbound`, `outbound`, `dst`, `user`, `proto`

---

## metrics

- `sb-metrics` 提供统一 API：counter/gauge/histogram
- adapters/core 只调用抽象接口，不直接绑定 prometheus
- prometheus exporter 由 app 或 sb-api 启动（控制面）

---

## 采样与成本

- trace 默认采样关闭或低采样；通过控制面动态调高
- 热路径禁止 `format!` 构造大字符串
