# Outbound Ports

## OutboundConnector

```rust
pub trait OutboundConnector: Send + Sync {
  fn tag(&self) -> OutboundTag;

  async fn connect_stream(&self, sess: &Session, target: &TargetAddr) -> Result<Box<dyn AsyncStream>, CoreError>;
  async fn send_datagram(&self, sess: &Session, target: &TargetAddr, data: &[u8]) -> Result<(), CoreError>;
}
```

要点：
- sb-core 只知道 tag 与 connector，不知道 VMess/VLESS/SS 等细节
- 连接复用、mux 等属于 adapter 内部
