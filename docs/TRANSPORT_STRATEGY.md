Transport Strategy — TLS/WS/H2/HUP/gRPC/mux

Scope
- Describe how OutboundIR maps to sb-transport chain.
- Document defaults and conflict resolution.

Derivation Rules
- Explicit chain wins: When `transport` chain is set (e.g., ["tls","ws"]) it is used verbatim.
- Hints to chain:
  - ws: present if `ws_path` or `ws_host` is set.
  - h2: present if `h2_path` or `h2_host` is set.
  - httpupgrade: present if `http_upgrade_path` or `http_upgrade_headers` is set.
  - grpc: present if `grpc_service` or `grpc_method` is set.
  - tls: inserted as the outermost layer when either `tls_sni` or `tls_alpn` is set.

Conflicts and Priority
- ws vs h2:
  - If both hints are present, prefer WebSocket and log a warning.
  - IR validation now errors when multiple application layers (ws/h2/httpupgrade/grpc) are specified (see sb-config::ir::ConfigIR::validate).
- grpc vs other layers:
  - grpc establishes its own channel; in builder it supersedes previous layers by design.
- tls position:
  - When derived, TLS is inserted first (outermost) before application layers.

Defaults
- No hints and no chain → raw TCP (no TLS).
- h2 without ALPN:
  - ALPN defaults to h2 when composing TLS.
- gRPC:
  - TLS is enabled when SNI/ALPN is provided or TLS appears explicitly in explicit chain.

Testing Notes
- Derivation is unit-tested in `sb-core/src/runtime/transport.rs` (derive_chain tests).
- Chain composition then feeds sb-transport::TransportBuilder; behavioral e2e relies on dialer integration tests.

Operational Guidance
- Prefer explicit `transport` for deterministic behavior across platforms.
- When using hints, avoid specifying multiple application layers simultaneously; use one of ws/h2/httpupgrade/grpc.

CLI/Debugging
- During runtime, the derived chain is logged at debug level with fields `chain`, `sni`, and `alpn` when composing transports.
- To inspect, run with `RUST_LOG=sb_core::transport=debug app run ...`.
