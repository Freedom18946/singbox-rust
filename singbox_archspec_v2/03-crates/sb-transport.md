# sb-transport（传输形态）

## 1) 职责

- 提供统一 transport 抽象：
  - TCP/UDP 基础
  - WebSocket / HTTP2 / gRPC / QUIC
  - mux（如有）
- 为 adapters 提供“连接构建器”与“统一 I/O traits”

## 2) 推荐依赖与版本（对齐现有仓库）

- tokio（net/time/io-util）
- rustls / tokio-rustls（通过 feature `transport_tls`）
- quinn（通过 feature `transport_quic`）
- socket2（socket options）
- thiserror / bytes

## 3) Public API（示例）

```rust
pub enum Transport {
  Tcp(TcpTransport),
  Ws(WsTransport),
  H2(H2Transport),
  Quic(QuicTransport),
}

impl Transport {
  pub async fn dial(&self, target: &TargetAddr) -> Result<Box<dyn AsyncStream>, TransportError>;
}
```

## 4) Feature 边界

- transport 相关 feature 只影响本 crate 内部实现，不改变上层依赖方向
- adapters 通过 feature 打开所需传输能力，但 app 负责最终聚合
