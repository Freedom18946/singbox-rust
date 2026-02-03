# sb-core（引擎层）

## 1) 职责（只能做这些）

- 路由与策略执行（RuleEngine）
- 会话编排（Session lifecycle）
- 资源治理：超时、熔断、健康、背压
- DNS 选择策略与缓存（不包含具体 resolver 实现）
- Outbound 选择与调度（不包含具体协议实现）

## 2) 禁止事项（出现即违规）

- `inbound/*` 或 `outbound/*` 协议实现
- `services/*` 平台服务实现
- 引入：axum/tonic/tower/hyper/reqwest/rustls/quinn/tokio-tungstenite 等

## 3) 核心对象（公共 API）

### Engine

```rust
pub struct Engine {
  router: Router,
  dns: Box<dyn DnsPort>,
  outbound: OutboundRegistry,
  metrics: Box<dyn MetricsPort>,
  admin: AdminState,
}

impl Engine {
  pub async fn handle_stream(&self, sess: Session, inbound: Box<dyn AsyncStream>) -> Result<(), CoreError>;
  pub async fn handle_datagram(&self, sess: Session, pkt: Datagram) -> Result<(), CoreError>;

  // 控制面接口（由 sb-api 调用）
  pub fn admin(&self) -> &dyn AdminPort;
}
```

### Router

- 输入：`Session`（包含 inbound tag、用户、目的地址、SNI 等）
- 输出：`RouteDecision { outbound_tag, dns_policy, sniff_policy, mark }`

## 4) 目录结构（建议）

```
sb-core/
  src/
    lib.rs
    engine.rs
    session_flow/
      mod.rs
      stream.rs
      datagram.rs
    router/
      mod.rs
      ir.rs
      matcher.rs
    policy/
      mod.rs
      timeout.rs
      circuit_breaker.rs
      rate_limit.rs
    dns/
      mod.rs
      cache.rs
      strategy.rs
    admin/
      mod.rs
      state.rs
```

## 5) 依赖（建议）

- `sb-types`, `sb-common`
- `tokio`（最小 feature：sync/time/task）
- `futures`（必要时）
- `tracing`（可选，但建议通过 `sb-common` re-export）
