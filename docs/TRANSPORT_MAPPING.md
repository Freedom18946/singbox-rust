Transport Mapping (OutboundIR → sb-transport)

Overview
- This document explains how OutboundIR maps to layered transports using sb-transport::TransportBuilder.
- Applies uniformly for VMess/VLESS/Trojan (and future protocols using the Switchboard connectors).

Chain and Defaults
- transport: if provided, layers are applied in-order (e.g., ["tls","ws"], ["tls","h2"], ["grpc"]).
- Derived chain (when transport is None):
  - ws_path/ws_host → ws
  - h2_path/h2_host → h2
  - http_upgrade_path/http_upgrade_headers → httpupgrade
  - grpc_service/grpc_method → grpc
  - tls: inserted automatically at the front when tls_sni or tls_alpn is present
- ALPN: when chain includes h2 and tls_alpn is missing, ALPN defaults to ["h2"].
- gRPC: enable TLS when TLS appears in chain, or tls_sni/tls_alpn indicates TLS.

Field Mapping
- TLS: tls_sni → SNI override; tls_alpn (CSV) → ALPN list
- WS: ws_path/ws_host → websocket::WebSocketConfig
- H2: h2_path/h2_host → http2::Http2Config
- HTTP Upgrade: http_upgrade_path/http_upgrade_headers → httpupgrade::HttpUpgradeConfig
- gRPC: grpc_service/grpc_method/grpc_authority/grpc_metadata → grpc::GrpcConfig
- Multiplex: presence of "mux"/"multiplex" in chain → multiplex::MultiplexConfig

Implementation Entry Points
- Runtime mapping helper: crates/sb-core/src/runtime/transport.rs (map::apply_layers / builder_from_ir)
- Switchboard connectors: crates/sb-core/src/runtime/switchboard.rs
- Protocol IO (VMess/VLESS/Trojan): switched to use apply_layers uniformly
- Adapter bridge (inbound-driven path): VMess/VLESS/Trojan now use apply_layers when feature "v2ray_transport" is enabled

Notes
- Trojan requires TLS; mapping always passes SNI to imply TLS
- When both explicit chain and fields are present, the chain has priority; fields fill layer configuration
- Shadowsocks/TUIC/Hysteria2/ShadowTLS: these protocols manage their own transports (AEAD/QUIC/TLS) and generally do not
  leverage the generic TransportBuilder chain. IR fields are still consumed by their constructors where applicable
  (e.g., ALPN for QUIC variants). Further mapping would require protocol-specific dialers and is not targeted in P0.
