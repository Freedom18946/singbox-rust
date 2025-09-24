<!--
  High-level architecture for singbox-rust.
  This document is intentionally verbose to serve as a newcomer-friendly guide.
-->

# singbox-rust Architecture (Phase 2.4)

> TL;DR: Small, boring, testable components — **pragmatism over theory**.

## Crates

- **sb-core**  
  Minimal platform-agnostic contracts: `net::Address`, `pipeline::{Inbound, Outbound}`, `router::{Router, StaticRouter, engine::RuleRouter}`.

- **sb-adapters**  
  Glue to the outside world. Inbounds (HTTP, SOCKS, TUN skeleton) and Outbounds (direct, block).

- **sb-config**  
  JSON IR parsers and compatibility shims (Go 1.12.4 "Present" schema).

- **sb-platform / sb-metrics**  
  Platform detections, metrics stubs, logging setup helpers.

- **app**  
  Binary: loads config/env, builds router/outbounds, starts inbounds.

## Data Flow

```
 ┌─────────┐     inbounds     ┌────────┐     select/connect     ┌──────────┐
 │  app    │ ───────────────▶ │ Router │ ─────────────────────▶ │ Outbound │
 └─────────┘                  └────────┘                        └──────────┘
       ▲                          ▲                                  ▲
       │                          │                                  │
       │          config/env      │           trait                   │
       └──────────────────────────┴───────────────────────────────────┘
```

## Router Engine

Rule granularity:

- `host_suffix: Option<String>`
- `transport: Option<String>`
- `inbound: Option<String>`
- `user: Option<String>`
- `target: Arc<dyn Outbound>`

**No special cases.** Multiple domain suffixes become multiple `Rule`s.

## Readiness Signaling

We replaced port polling with **oneshot channel** (`serve_with_ready`), eliminating flakiness in CI.

## Feature Matrix

| Feature | Crate         | Notes                    |
|--------:|---------------|--------------------------|
| http    | sb-adapters   | HTTP CONNECT inbound     |
| socks   | sb-adapters   | SOCKS5 inbound           |
| tun     | sb-adapters   | utun skeleton (macOS)    |
| full    | workspace     | http + socks + tun       |

## Compatibility

- `EngineRouter` type alias kept for legacy.
- Go Present schema supported in `sb-config`.

## Testing Strategy

- **Unit**: adapters + config goldens.
- **E2E**: `http_connect_smoke.rs`, `http_router_roundtrip.rs`.

> _Never break userspace_ — we add, we don't remove.