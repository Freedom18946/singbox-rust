Transport Fallback (WS/H2/Upgrade)

Overview
- When multiple application-layer transports are feasible (e.g., WebSocket vs HTTP/2), an initial chain can fail due to upstream capabilities or middleboxes.
- A lightweight fallback mechanism is available for VMess/VLESS/Trojan (sb-transport path) to try an alternate chain automatically.

Enable/Disable
- Env: SB_TRANSPORT_FALLBACK (default: true)
  - "1" / "true" (case-insensitive) enables attempts.
  - Any other value disables fallbacks (primary chain only).

Fallback plan
- Primary: derived by IR → chain (see transport-defaults.md)
- If primary is `tls,ws` and H2 hints exist → try `tls,h2`
- If primary is `tls,h2` and WS hints exist → try `tls,ws`
- If primary contains `httpupgrade` and WS hints exist → try `ws` (or `tls,ws` if TLS implied)
- Planning helper: `fallback_chains_from_ir()` (no network I/O) exposed for testing.

Metrics
- Counter: `transport_fallback_total{reason,mode,result}`
  - reason: `primary_failed`
  - mode: alternate chain label (e.g., `tls->h2`)
  - result: `attempt|ok|fail`

Notes
- Scope: VMess/VLESS/Trojan with `v2ray_transport`. Other protocols can adopt this pattern incrementally.
- Safety: Fallback attempts log a warning; attempts stop after the small finite plan derived from IR hints.

