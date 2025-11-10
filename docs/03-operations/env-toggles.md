Environment Toggles

SB_TRANSPORT_FALLBACK
- Enables transport fallback attempts when primary chain fails (VMess/VLESS/Trojan via sb-transport).
- Default: true
- Values: "1" / "true" (enable), anything else disables.
- Metrics: `transport_fallback_total{reason,mode,result}`, `transport_fallback_ms{mode}`.

SB_TRANSPORT_SNI_FALLBACK
- Enables SNI fallback in transport builder when TLS is implied by hints (H2/gRPC) but no SNI provided.
- Default: true
- Values: "1" / "true" (enable), anything else disables.
- See: `builder_from_ir` in `crates/sb-core/src/runtime/transport.rs`.

