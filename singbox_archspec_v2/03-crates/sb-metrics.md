# sb-metrics（观测抽象与导出）

## 1) 职责

- 定义统一 metrics API（counter/gauge/histogram）
- 提供默认实现（prometheus 等）但让数据面只依赖抽象

## 2) 建议 API

```rust
pub trait MetricsPort: Send + Sync {
  fn inc_counter(&self, name: &'static str, labels: &[(&'static str, &str)], v: u64);
  fn observe_hist(&self, name: &'static str, labels: &[(&'static str, &str)], v: f64);
}
```

## 3) 禁止事项

- 不在 sb-core/sb-adapters 内直接依赖 prometheus 类型；只通过 MetricsPort
