# 控制面 Ports（Admin/Stats/Diag）

## AdminPort

```rust
pub trait AdminPort: Send + Sync {
  fn reload_config(&self, raw: Vec<u8>) -> Result<(), CoreError>;
  fn shutdown(&self) -> Result<(), CoreError>;
  fn set_log_level(&self, level: LogLevel) -> Result<(), CoreError>;
}
```

## StatsPort

```rust
pub trait StatsPort: Send + Sync {
  fn connections(&self) -> Vec<ConnSnapshot>;
  fn traffic(&self) -> TrafficSnapshot;
}
```

> 注意：控制面必须是同步接口或短任务，避免把长耗时 I/O 混入查询端点。
> 若必须 async，请采用 object-safe wrapper（见 templates）。
