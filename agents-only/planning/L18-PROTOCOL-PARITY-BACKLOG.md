# L18 Protocol Parity Backlog

Date: 2026-03-11

Goal: produce reproducible protocol parity evidence against Go `sing-box 1.12.14` without relying on historical "production ready" wording.

## Current status

- Trojan: established on local dual-kernel dataplane.
  - New case: `labs/interop-lab/cases/p2_trojan_dual_dataplane_local.yaml`.
  - Clean dual-kernel diff achieved on run `20260310T144229Z-73c29cc4-8f0b-4491-9c9b-2fb7ce271dea`.
  - Evidence:
    - `labs/interop-lab/artifacts/manual_protocols/p2_trojan_dual_dataplane_local/20260310T144229Z-73c29cc4-8f0b-4491-9c9b-2fb7ce271dea/rust.snapshot.json`
    - `labs/interop-lab/artifacts/manual_protocols/p2_trojan_dual_dataplane_local/20260310T144229Z-73c29cc4-8f0b-4491-9c9b-2fb7ce271dea/go.snapshot.json`
    - `labs/interop-lab/artifacts/manual_protocols/p2_trojan_dual_dataplane_local/20260310T144229Z-73c29cc4-8f0b-4491-9c9b-2fb7ce271dea/diff.md`
- Shadowsocks: established on local dual-kernel dataplane.
  - New case: `labs/interop-lab/cases/p2_shadowsocks_dual_dataplane_local.yaml`.
  - Clean dual-kernel diff achieved on run `20260310T150018Z-0741eaa5-4d63-4576-8348-163e072b3a86`.
  - Evidence:
    - `labs/interop-lab/artifacts/manual_protocols/p2_shadowsocks_dual_dataplane_local/20260310T150018Z-0741eaa5-4d63-4576-8348-163e072b3a86/rust.snapshot.json`
    - `labs/interop-lab/artifacts/manual_protocols/p2_shadowsocks_dual_dataplane_local/20260310T150018Z-0741eaa5-4d63-4576-8348-163e072b3a86/go.snapshot.json`
    - `labs/interop-lab/artifacts/manual_protocols/p2_shadowsocks_dual_dataplane_local/20260310T150018Z-0741eaa5-4d63-4576-8348-163e072b3a86/diff.md`
  - Root fixes that were required:
    - replace the non-standard SHA1 pseudo-KDF with standard Shadowsocks EVP_BytesToKey,
    - include `ATYP+ADDR+PORT` in Rust UDP responses instead of returning payload-only ciphertext.
- ShadowTLS: partial.
  - The previous Rust adapter/test path was validating a legacy `TLS + HTTP CONNECT` tunnel model, not sing-box ShadowTLS semantics.
  - As of 2026-03-10, standalone leaf dialing is intentionally blocked by `crates/sb-adapters/tests/shadowtls_e2e.rs` so the legacy model stops contaminating parity claims.
  - As of 2026-03-11, the IR/validator/builder path now models `shadowtls.password`, `shadowtls.version`, and generic outbound `detour`, so the config surface is aligned with the upcoming transport-wrapper remodel instead of the legacy tunnel shortcut.
  - Verified on 2026-03-11 with:
    - `cargo test -p sb-config shadowtls_validation_reports_missing_password_and_bad_version -- --nocapture`
    - `cargo test -p sb-config outbound_ir_deserializes_detour_and_shadowtls_version -- --nocapture`
    - `cargo test -p sb-adapters --test shadowtls_e2e --features adapter-shadowtls -- --nocapture`
    - `cargo build -p interop-lab`
  - The current Rust `shadowtls` adapter remains registrable, but runtime use is now explicitly outside parity scope until transport-wrapper chaining is implemented.
  - Dual-kernel Go/Rust parity is still not established.
  - New local dual-kernel case exists:
    - `labs/interop-lab/cases/p2_shadowtls_dual_dataplane_local.yaml`
  - Fresh dual-kernel gap observed on run `20260310T152408Z-10dee6a6-abba-4a6e-a319-c7540aee4339`:
    - Rust: `stl_tcp_ok=true`, `stl_tcp_strict_cert=false`
    - Go: `stl_tcp_ok=false`, `stl_tcp_strict_cert=false`
    - Diff report: `labs/interop-lab/artifacts/manual_protocols/p2_shadowtls_dual_dataplane_local/20260310T152408Z-10dee6a6-abba-4a6e-a319-c7540aee4339/diff.md`
  - Current diagnosis:
    - Go oracle accepted the `shadowtls` config and routed traffic into `outbound/shadowtls[stl-ok]`.
    - Rust managed `shadowtls` inbound logged protocol-level failures for the Go positive path (`InvalidContentType` / TLS alert path), so this is not just a route miss.
    - The mismatch looks structural, not incidental: current Rust `shadowtls` code is a TLS + HTTP CONNECT tunnel, while Go `sing-box` documents `version/password/users/handshake` semantics for ShadowTLS.
    - More specifically, Go `protocol/shadowtls/outbound.go` ignores the requested destination and returns `client.DialContext(ctx)`, while current Rust `outbound/shadowtls.rs` serializes `CONNECT host:port HTTP/1.1` to the server. The present local direct-tunnel case is therefore a divergence probe, not a final semantically-correct parity target.

## Batch 1: Trojan dual-kernel closeout

- Status: done.
- Follow-up only if we want to extend beyond the current minimum matrix:
  - add a recovery path,
  - add a second TLS/cert variant,
  - archive the clean diff into the verification record.

## Batch 2: Shadowsocks dual-kernel closeout

- Status: done.
- Follow-up only if we want to extend beyond the current minimum matrix:
  - add a second cipher after `aes-256-gcm`,
  - archive the clean diff into the verification record,
  - decide whether to retain the new tracing init in `interop-lab` as standard harness behavior.

## Batch 3: ShadowTLS model guardrail

- Status: done.
- Implemented in `crates/sb-adapters/tests/shadowtls_e2e.rs`.
- What is now covered:
  - standalone `shadowtls` leaf dialing is rejected with a stable error,
  - rejection happens before any network handshake or misleading "success" path.
- Remaining follow-up before any parity claim:
  - redesign Rust ShadowTLS as a transport wrapper/detour instead of a destination-carrying leaf connector,
  - finish the runtime half of the new config model so `detour`-capable leaf outbounds can actually dial over ShadowTLS,
  - add the remaining Go-compatible `users/handshake/strict_mode/wildcard_sni` semantics,
  - either rebuild `interop-lab` around a semantically correct wrapper case or add a dedicated compatibility harness that proves the Go outbound path against the remodeled Rust server,
  - only after that, rerun the ShadowTLS dual-kernel case and decide whether to extend to more TLS/SNI variants.

## Batch 4: ShadowTLS runtime remodel

- Status: next.
- Minimum executable target:
  - teach leaf outbounds to honor outbound `detour`,
  - let ShadowTLS provide a transport stream instead of serializing destination metadata itself,
  - re-run the existing divergence probe only after the wrapper chain is live.

## Rules for evidence updates

- Mark status as `established` only when there is fresh, reproducible evidence from the current code.
- Mark status as `partial` when evidence is single-kernel, sandbox-limited, or missing negative/recovery coverage.
- Mark status as `not established` when only config/smoke tests exist.
- Do not reuse old "production ready" wording unless the new evidence set actually supports it.
