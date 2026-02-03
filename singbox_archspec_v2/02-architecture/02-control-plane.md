# 控制面（Control Plane）原则

## sb-api 的边界

- sb-api 只做：
  - HTTP/gRPC server
  - 请求解析/鉴权
  - 调用 sb-core 暴露的 `AdminPort`/`StatsPort` 等接口
  - 序列化响应

禁止：
- 直接操作 sb-adapters（否则控制面与协议耦合）
- 在 sb-core 内嵌入任何 Web 框架

---

## 管理接口 Ports（示例）

- `AdminPort`：配置热更新、启停、切换路由集、导出状态
- `StatsPort`：流量统计、连接列表、延迟/失败率
- `DiagPort`：追踪开关、dump、健康检查

Ports 定义见 `04-interfaces/admin.md`
