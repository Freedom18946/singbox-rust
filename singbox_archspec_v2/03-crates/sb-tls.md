# sb-tls（TLS/Reality/ECH）

## 1) 职责

- TLS 握手配置与策略封装
- Reality/ECH 等扩展能力（通过 feature gate）
- 证书加载与验证策略（但“配置来源”由 sb-platform 或 app 负责）

## 2) 禁止事项

- 不允许依赖 sb-core
- 不允许包含控制面 API

## 3) 建议 API

```rust
pub struct TlsClientConfig { /* ... */ }

pub async fn connect_tls(
  tcp: Box<dyn AsyncStream>,
  sni: &str,
  cfg: &TlsClientConfig,
) -> Result<Box<dyn AsyncStream>, TlsError>;
```
