# sb-api（控制面 API）

## 1) 职责

- 提供 Clash API / V2Ray API 等管理接口
- 调用 sb-core 暴露的 Admin/Stats/Diag Ports
- 负责鉴权、CORS、WebSocket 订阅（如有）

## 2) 依赖规则

允许：
- axum / tower / tonic 等 Web 框架
- sb-core（仅管理接口）
- sb-config（用于热更新入参解析）

禁止：
- 直接依赖 sb-adapters
- 把 Web 框架依赖引入 sb-core

## 3) 管理接口必须以 trait 注入

```rust
pub struct ApiState {
  admin: Arc<dyn AdminPort>,
  stats: Arc<dyn StatsPort>,
}
```
