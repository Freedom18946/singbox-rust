# Go vs Rust Diff Analysis (2026-01-31)

## Baseline

- Go reference: `go_fork_source/sing-box-1.12.14`
- Rust reference: current workspace state (singbox-rust)
- Scope: protocol coverage, TLS/crypto behavior, endpoints/services parity, and feature gates

## Executive Summary

- Overall parity: **183/209 (88%)** aligned, **15** partial, **3** not aligned, **4** de-scoped, **4** Rust-only.
- Primary deltas remain in TLS handshake fidelity, WireGuard endpoint userspace limits, and Tailscale endpoint de-scope.
- Feature-gated registrations still mean default builds do not fully match Go behavior.

## Key Differences (Highest Impact)

1. **Feature gates (parity build)**
   - Rust registers stubs unless `parity`/adapter/service/DNS features are enabled.
   - Go builds ship full feature set by default.

2. **REALITY (TLS)**
   - Rust client cert verification is permissive (does not distinguish proxy vs fallback cert).
   - Rust server uses placeholder session data and does not implement certificate stealing.
   - Go implements full REALITY semantics.

3. **ECH (TLS)**
   - Rust implements config parsing + HPKE but lacks rustls handshake integration.
   - Go provides working ECH handshake behavior.

4. **uTLS fingerprinting**
   - Rust provides best-effort cipher suite/ALPN ordering via rustls; full ClientHello ordering parity is not possible with current rustls.
   - Go uses uTLS for real ClientHello mimicry.

5. **WireGuard endpoint (userspace)**
   - Rust userspace endpoint cannot support UDP listen/reserved bytes due to Endpoint trait requiring OS `UdpSocket`.
   - Go endpoint supports these behaviors in parity configurations.

6. **Tailscale endpoint**
   - Rust endpoint is de-scoped (daemon-only) vs Go tsnet + gVisor integration.

## References

- `GO_PARITY_MATRIX.md`
- `NEXT_STEPS.md`
- `docs/STATUS.md`
