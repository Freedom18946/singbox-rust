# Inbound Ports

## InboundAcceptor

```rust
pub trait InboundAcceptor: Send + Sync {
  fn tag(&self) -> InboundTag;

  async fn accept_loop(&self, handler: InboundHandler) -> Result<(), CoreError>;
}

pub trait InboundHandler: Send + Sync + 'static {
  async fn on_stream(&self, sess: Session, stream: Box<dyn AsyncStream>) -> Result<(), CoreError>;
  async fn on_datagram(&self, sess: Session, pkt: Datagram) -> Result<(), CoreError>;
}
```

要点：
- accept_loop 由 adapter 拥有监听 socket
- handler 由 sb-core 提供（Engine 实现）
