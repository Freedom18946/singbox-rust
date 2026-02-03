# 模板：object-safe async wrapper（用于扩展点）

当你必须使用 `dyn Trait` 且需要 async：

```rust
use std::{future::Future, pin::Pin};

pub trait AdminPort: Send + Sync {
  fn reload_config(&self, raw: Vec<u8>)
    -> Pin<Box<dyn Future<Output = Result<(), CoreError>> + Send + '_>>;
}
```

实现端可以用 `async fn` 并 `Box::pin(async move { ... })` 包装。
