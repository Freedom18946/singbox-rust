# 配置编译落地细节（coding agent 级别）

## 输入与输出类型（固定）

- 输入：`RawConfig`（sb-config）
- 输出：`ConfigIr`（sb-types）

### ConfigIr 必须包含

- 已归一化的 inbound/outbound 列表（带 tag）
- 路由规则 IR（已预编译 matcher）
- DNS 策略（每 outbound/每 route 的策略已解析）
- feature 需求摘要（用于 app 在启动时校验组件是否齐备）

```rust
pub struct FeatureDemand {
  pub need_quic: bool,
  pub need_tls: bool,
  pub need_tun: bool,
  pub need_reality: bool,
}
```

## 编译期校验（必须）

- 引用完整性：rule 引用的 outbound tag 必须存在
- 能力校验：如果 IR 表示需要 QUIC，但 app 未开启 `transport_quic`，启动直接失败（清晰报错）
