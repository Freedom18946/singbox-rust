# 错误模型（Error Model）

## 总原则

- **领域错误 typed**：在 `sb-types` 定义核心错误枚举（可跨 crate 传播，便于匹配与策略处理）
- **边界处可降级为 anyhow**：仅限 binary（app）或控制面（sb-api）作为“最后一公里”错误包装
- **不要在热路径上频繁构造字符串**：错误消息要 lazy 或静态化

---

## 分层规则

### sb-types：定义可稳定匹配的错误类型

- `enum CoreError { Io, Timeout, Dns, Auth, Protocol, Policy, ResourceExhausted, Internal }`
- 每个 variant 有明确字段：如 `Timeout { op: Op, dur: Duration }`
- 建议统一 error code（用于 API/metrics）：`CoreErrorCode`

### sb-core：只使用 typed errors

- 不允许 `anyhow::Error` 在 core 内部传播
- 提供 `impl From<...> for CoreError` 的转换

### sb-adapters/sb-transport/sb-platform：内部错误允许更细，但对外统一映射

- adapters 可有 `enum AdapterError`，最终在实现 Ports 时映射为 `CoreError` 或 `TransportError`

---

## 日志策略

- 错误返回时不要强制 log（避免重复）；由调用者决定是否记录
- 但在“吞掉错误”时必须 log（例如回退策略/降级路径）
