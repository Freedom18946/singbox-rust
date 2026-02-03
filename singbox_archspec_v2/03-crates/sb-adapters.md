# sb-adapters（协议适配器层）

## 1) 职责

- 实现所有 inbound/outbound 协议
- 将协议差异适配到 `sb-types` 定义的 Ports
- 仅在本 crate 内处理协议细节（握手、加密、封包、mux、obfs…）

## 2) 禁止事项

- 不允许依赖 sb-core（除了极少数共享类型，原则上也应移入 sb-types）
- 不允许实现控制面 server（HTTP/gRPC）——属于 sb-api

## 3) 目录结构（建议）

```
sb-adapters/
  src/
    lib.rs
    inbound/
      mod.rs
      socks.rs
      http.rs
      ...
    outbound/
      mod.rs
      direct.rs
      socks.rs
      vmess.rs
      ...
    endpoint/
      mod.rs
      wireguard.rs
      tailscale.rs
    services/
      mod.rs
      resolved.rs
      derp.rs
    factory/
      mod.rs
      build_from_ir.rs
    util/
      ...
```

## 4) 工厂接口（必须）

sb-adapters 必须提供“从 IR 构建组件”的统一入口，供 app 组装：

```rust
pub struct AdapterSet {
  pub inbounds: Vec<Box<dyn InboundAcceptor>>,
  pub outbounds: OutboundSet, // enum 或 registry
  pub endpoints: EndpointSet,
}

pub fn build_adapters(ir: &ConfigIr, deps: AdapterDeps) -> Result<AdapterSet, AdapterError>;
```

## 5) 分发策略

- Outbound/Inbound 在热路径必须是 enum 分发（见 templates/enum-dispatch.md）
- dyn 仅用于低频扩展点（例如少量可插拔服务）
