# sb-types（契约层）

## 1) 职责

- 定义 **所有跨 crate 的稳定数据结构**：
  - `Session`, `TargetAddr`, `InboundTag`, `OutboundTag`
  - `ConfigIr`（可选：如果 IR 需要跨 crate 共享）
- 定义 **Ports（trait）**：
  - `InboundPort`, `OutboundPort`, `DnsPort`, `TransportPort`, `AdminPort`, `MetricsPort`
- 定义 **typed errors**：
  - `CoreError`, `DnsError`, `TransportError` 等

## 2) 禁止事项

- 不允许依赖：tokio、HTTP/TLS/QUIC/WS 等实现库
- 不允许包含任何 I/O

## 3) 推荐依赖（最小集合）

- `thiserror`（或仅 std error）
- `serde`（可选）
- `bytes`（可选）
- `ipnet`（可选）

## 4) 目录结构（建议）

```
sb-types/
  src/
    lib.rs
    session.rs
    addr.rs
    tags.rs
    errors.rs
    ports/
      mod.rs
      inbound.rs
      outbound.rs
      dns.rs
      admin.rs
      metrics.rs
```

## 5) Ports 示例（片段）

```rust
// ports/outbound.rs
use crate::{Session, CoreError, TargetAddr};

pub trait OutboundConnector: Send + Sync + 'static {
    fn name(&self) -> &'static str;

    async fn connect_stream(
        &self,
        session: &Session,
        target: &TargetAddr,
    ) -> Result<Box<dyn AsyncStream>, CoreError>;

    async fn send_datagram(
        &self,
        session: &Session,
        target: &TargetAddr,
        data: &[u8],
    ) -> Result<(), CoreError>;
}
```

> 注意：如果需要 `dyn Trait`，则改用 object-safe wrapper（见 templates）。
