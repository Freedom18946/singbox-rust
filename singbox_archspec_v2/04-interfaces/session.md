# Session 与 TargetAddr 规范

## Session（不可随意膨胀）

Session 是数据面贯穿对象。规则：
- 必须可廉价 clone（优先 Arc/SmallVec）
- 字段分为：
  - 身份：sid、user、inbound tag
  - 目的：target addr、SNI/ALPN
  - 元信息：协议、sniff 结果、mark

建议结构：

```rust
pub struct Session {
  pub sid: u64,
  pub inbound: InboundTag,
  pub user: Option<UserId>,
  pub target: TargetAddr,
  pub meta: SessionMeta,
}
```

---

## TargetAddr

- 支持域名/IPv4/IPv6/端口
- 必须支持“延迟解析”（域名先不解析，路由决定后再解析）
