# DNS Ports

## DnsPort

```rust
pub trait DnsPort: Send + Sync {
  async fn resolve_ip(&self, name: &str) -> Result<Vec<std::net::IpAddr>, DnsError>;
  fn cache_stats(&self) -> DnsCacheStats;
}
```

## 设计要点

- sb-core 负责 DNS 策略（何时解析、是否优先 v6）
- sb-platform 可以提供 system resolver；sb-adapters 可以提供 DoH/DoT 等 resolver（作为实现）
