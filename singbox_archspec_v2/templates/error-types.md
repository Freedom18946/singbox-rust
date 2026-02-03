# 模板：typed error（sb-types）

```rust
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CoreError {
  #[error("io: {0}")]
  Io(#[from] std::io::Error),

  #[error("timeout: op={op:?}, dur={dur:?}")]
  Timeout { op: Op, dur: std::time::Duration },

  #[error("dns: {0}")]
  Dns(String),

  #[error("policy denied: {reason}")]
  Policy { reason: &'static str },

  #[error("internal")]
  Internal,
}
```

规则：
- variant 要可稳定匹配
- 字段尽量结构化，不要塞整段字符串
