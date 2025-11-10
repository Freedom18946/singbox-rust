Transport Defaults and Conflict Handling

Overview
- Purpose: document how OutboundIR fields map to sb-transport layers and what defaults apply.
- Scope: TLS, WebSocket, HTTP/2, HTTP Upgrade, gRPC, and mux composition in the client stack.

Defaults
- TLS enablement:
  - Enabled when either explicit transport chain contains `tls`, or when `tls_sni` is provided.
  - ALPN: if HTTP/2 or gRPC is present and no ALPN is declared, ALPN defaults to `h2`.
- WebSocket (ws):
  - `ws_path` and/or `ws_host` imply `ws` layer; `Host` header is set when `ws_host` is provided.
- HTTP/2 (h2):
  - `h2_path` and/or `h2_host` imply `h2` layer; ALPN defaults to `h2` when TLS is enabled.
- HTTP Upgrade (httpupgrade):
  - `http_upgrade_path` or `http_upgrade_headers` imply HTTP Upgrade layer.
- gRPC (grpc):
  - `grpc_service/method/authority/metadata` imply `grpc` layer.
  - TLS is not implicitly enabled unless SNI/ALPN indicates TLS or `tls` is in the chain.
- Mux (yamux):
  - Enabled only when requested in the explicit chain.

Conflict handling
- Application-layer transports `ws`, `h2`, `httpupgrade`, and `grpc` are mutually exclusive in OutboundIR.
- The IR validator rejects configuration when more than one is selected via chain or hint fields.
- If conflicting hints are provided, derive logic prefers WebSocket over HTTP/2 and emits a warning.

Fallback plan (experimental)
- We expose a planning helper that derives alternative chains (no network I/O):
  - Primary: `derive_chain()` result
  - If primary is `tls,ws` and H2 hints exist, next: `tls,h2`
  - If primary is `tls,h2` and WS hints exist, next: `tls,ws`
  - If primary contains `httpupgrade` and WS hints exist, next: `ws` (or `tls,ws` if SNI/ALPN implies TLS)
- This is not yet wired to active dialing; once implemented, metrics will be emitted as `transport_fallback_total{from,to,result}`.

Test coverage
- Contract tests live in `crates/sb-core/src/runtime/transport.rs`:
  - `derive_chain_ws_prefers_over_h2_with_tls`: WS wins when both WS and H2 hints exist.
  - `derive_chain_httpupgrade_with_tls`: Upgrade + TLS inferred from SNI.
  - `derive_chain_respects_explicit_chain`: explicit chain is honored.
  - `derive_chain_tls_only_when_only_tls_hints`: TLS only when only TLS hints are present.
  - `derive_chain_h2_defaults_tls_with_sni`: H2 implies TLS when SNI present, ALPN defaults to h2.

Notes
- Behavior aligns with NEXT_STEPS “WS1” plan; ECH remains experimental/unavailable.
- Failure fallback (e.g., WS/H2/Upgrade negotiation failures) is to be documented and wired under a separate feature gate.
