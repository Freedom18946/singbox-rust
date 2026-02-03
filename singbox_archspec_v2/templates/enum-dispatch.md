# 模板：enum 静态分发（用于热路径）

```rust
pub enum Outbound {
  Direct(DirectOutbound),
  Socks(SocksOutbound),
  Vmess(VmessOutbound),
}

impl Outbound {
  pub async fn connect_stream(&self, sess: &Session, target: &TargetAddr)
    -> Result<Box<dyn AsyncStream>, CoreError>
  {
    match self {
      Outbound::Direct(o) => o.connect_stream(sess, target).await,
      Outbound::Socks(o) => o.connect_stream(sess, target).await,
      Outbound::Vmess(o) => o.connect_stream(sess, target).await,
    }
  }
}
```

要点：
- enum 的构造发生在启动/热更新（非热路径）
- match 分发在热路径，避免 boxing 与 vtable
