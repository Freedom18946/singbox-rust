# 路由接口与 IR

## RouteDecision

```rust
pub struct RouteDecision {
  pub outbound: OutboundTag,
  pub dns: DnsPolicy,
  pub sniff: SniffPolicy,
  pub mark: u32,
}
```

## RouterPort（sb-core 内部对象，可不作为 port）

- 输入：Session（可能包含 sniff 信息）
- 输出：RouteDecision
- 必须从 Config IR 构建（避免运行期解析规则）
