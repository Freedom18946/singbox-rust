# Logging & Metrics 落地规范

## Logging

- 使用 tracing
- 事件级别：
  - INFO：生命周期（启动/热更新/监听端口）
  - WARN：可恢复错误（重试/降级/回退）
  - ERROR：不可恢复错误（会话终止、初始化失败）

## Metrics 命名规范

- 前缀：`sb_`
- 示例：
  - `sb_outbound_connect_total{outbound="vmess",result="ok"}`
  - `sb_outbound_connect_seconds_bucket{...}`
  - `sb_dns_resolve_seconds_bucket{...}`
