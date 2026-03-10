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
  - As of 2026-03-11, the IR/validator/builder path models `shadowtls.password`, `shadowtls.version`, and generic outbound `detour`, and the runtime path now supports the minimum real `version = 1` wrapper behavior: perform a TLS 1.2 camouflage handshake, then hand the raw TCP stream back to the chained outbound.
  - Verified on 2026-03-11 with:
    - `cargo test -p sb-config shadowtls_validation_reports_missing_password_and_bad_version -- --nocapture`
    - `cargo test -p sb-config outbound_ir_deserializes_detour_and_shadowtls_version -- --nocapture`
    - `cargo test -p sb-config inbound_ir_deserializes_shadowtls_runtime_fields -- --nocapture`
    - `cargo test -p sb-adapters --test shadowtls_e2e --features adapter-shadowtls -- --nocapture`
    - `cargo test -p sb-adapters --features adapter-shadowtls,adapter-shadowsocks shadowtls_ -- --nocapture`
    - `cargo test -p sb-adapters --features adapter-shadowtls,adapter-shadowsocks --test shadowtls_inbound_e2e -- --nocapture`
    - `cargo test -p sb-adapters --features adapter-trojan detour_ --lib -- --nocapture`
    - `cargo test -p sb-adapters --features adapter-trojan trojan_config_ --test trojan_integration -- --nocapture`
    - `cargo test -p sb-adapters --features adapter-shadowsocks --test shadowsocks_integration -- --nocapture`
    - `cargo test -p sb-adapters --features adapter-shadowsocks shadowsocks_ --lib -- --nocapture`
    - `cargo test -p sb-adapters --features adapter-shadowtls,adapter-shadowsocks --test shadowtls_e2e -- --nocapture`
    - `cargo test -p app --features adapters --test shadowtls_detour_chain_app -- --nocapture`
    - `cargo build -p interop-lab`
    - `cargo check -p app --features adapters --tests`
    - `cargo run -p interop-lab -- case run p2_shadowtls_dual_dataplane_local --kernel rust`
    - `INTEROP_GO_BINARY=reports/l18/oracle/go/shadowtls-interop-11214/sing-box cargo run -p interop-lab -- case run p2_shadowtls_dual_dataplane_local --kernel go`
    - `INTEROP_GO_BINARY=reports/l18/oracle/go/shadowtls-interop-11214/sing-box cargo run -p interop-lab -- case run p2_shadowtls_dual_dataplane_local`
  - The current Rust `shadowtls` adapter remains registrable, with parity evidence now limited to the detour-only `version = 1` wrapper path. Standalone leaf dialing remains intentionally out of scope.
  - Minimum dual-kernel Go/Rust parity is now established for the local `Shadowsocks -> detour=ShadowTLS(v1)` wrapper-chain case.
  - New local dual-kernel case exists:
    - `labs/interop-lab/cases/p2_shadowtls_dual_dataplane_local.yaml`
  - Historical gap note:
    - earlier runs `20260310T174026Z-46036dbc-e5b3-4e68-a052-e7496ed7fefb` and `20260310T174553Z-55d226bb-1118-4631-b4e2-37cd6ebc540e` failed the Go positive path with `unexpected EOF`, which turned out to be caused by a wrong Rust-side model that terminated TLS and forwarded plaintext instead of emulating ShadowTLS v1 handshake-only wrapping.
  - Current v1 wrapper-chain evidence on 2026-03-11:
    - `crates/sb-adapters/src/outbound/shadowtls.rs` now performs a TLS 1.2 handshake for camouflage and returns the raw stream for `version = 1`,
    - `labs/interop-lab/src/upstream.rs` now models the server side as `TLS record relay for handshake -> raw TCP relay for payload`, instead of TLS termination,
    - Rust-only run `20260310T175904Z-9e2ab106-0ad1-4b4f-8f2d-86ea9b0e47ba` passed with `stl_tcp_ok=true`, `stl_tcp_strict_cert=false`, `errors.count=0`,
    - Go-only run `20260310T180019Z-c0f1a5a0-cb3f-4073-b8ce-b3a33892c8c7` passed with the same outcome against a freshly rebuilt oracle from `go_fork_source/sing-box-1.12.14`,
    - combined dual-kernel run `20260310T180117Z-a452c721-28f9-452d-954f-ceffe0e4e3e6` produced matching Rust/Go snapshots for both the positive path and the strict-cert negative path.
  - Additional runtime/config progress on 2026-03-11:
    - `crates/sb-adapters/src/outbound/shadowtls.rs` now supports outbound `version = 2` in detour mode by preserving the handshake hash prefix and switching the returned stream to ShadowTLS v2 application-data framing after TLS camouflage,
    - `crates/sb-adapters/tests/shadowtls_e2e.rs` now covers direct v2 echo and `Shadowsocks -> detour=ShadowTLS(v2)` dial success,
    - inbound-side `detour`, `users/handshake/strict_mode/wildcard_sni` fields now deserialize through IR/bridge into a real ShadowTLS inbound runtime instead of being dropped or force-routed into the legacy TLS+CONNECT implementation,
    - `crates/sb-core/src/adapter/registry.rs` and `crates/sb-core/src/adapter/bridge.rs` now install a runtime inbound handle as well, so ShadowTLS inbound can late-bind its chained consumer by tag,
    - the first real inbound consumer is `ShadowsocksInboundAdapter::accept_detour_stream()`, and `crates/sb-adapters/tests/shadowtls_inbound_e2e.rs` proves `Shadowsocks(out) -> detour=ShadowTLS(v2 out) -> ShadowTLS(v2 in) -> Shadowsocks(in) -> echo`,
    - adapter-local unit coverage now also locks `version = 3` handshake target selection for `handshake_for_server_name` and `wildcard_sni`,
    - vendored `rustls 0.23.35` now carries a live client-hello `session_id` generator hook, wired into the workspace through `[patch.crates-io]`,
    - `crates/sb-adapters/src/outbound/shadowtls.rs` now implements outbound `version = 3` on the Go-like path: inject the authenticated `session_id` into the real TLS transcript, unwrap handshake-phase server `application_data`, then switch to a verified ShadowTLS v3 bridge,
    - `crates/sb-adapters/tests/shadowtls_inbound_e2e.rs` now proves `Shadowsocks(out) -> detour=ShadowTLS(v3 out) -> ShadowTLS(v3 in) -> Shadowsocks(in) -> echo`.

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
- Follow-up only if we later reshape the runtime again:
  - keep the guardrail aligned with the detour-only wrapper model,
  - avoid reintroducing the old standalone `TLS + HTTP CONNECT` claim surface.

## Batch 4: ShadowTLS runtime remodel

- Status: bounded scope done; overall protocol status remains `partial`.
- Minimum executable target:
  - teach leaf outbounds to honor outbound `detour`,
  - let ShadowTLS provide a transport stream instead of serializing destination metadata itself,
  - re-run the existing divergence probe only after the wrapper chain is live.
- Done on 2026-03-11:
  - installed a runtime outbound-registry handle in `sb-core::adapter::registry` so adapter outbounds can resolve `detour` late instead of depending on build order,
  - added `sb-adapters::outbound::detour::connect_tcp_stream()` as the shared TCP underlay helper,
  - switched Trojan to carry `detour` in config and honor it for plain-TCP underlay dialing,
  - switched Shadowsocks to carry `detour` in config and reuse the same helper for non-multiplex TCP tunnel dialing,
  - explicitly kept the boundary narrow: Shadowsocks detour currently rejects UDP relay and `multiplex` instead of silently bypassing the wrapper path,
  - remodeled ShadowTLS outbound so standalone leaf dialing is still rejected, while detour-mode `connect_io()` now performs the Go-compatible `version = 1` TLS 1.2 camouflage handshake and then yields the raw transport stream,
  - extended that outbound runtime to `version = 2` as well, using a post-handshake ShadowTLS v2 record bridge for the returned detour stream,
  - validated that wrapper path with a real chained consumer: `Shadowsocks -> detour=ShadowTLS(v1)` now completes a mock Shadowsocks handshake through a ShadowTLS v1 raw relay,
  - added adapter-level coverage that `Shadowsocks -> detour=ShadowTLS(v2)` also dials successfully through a ShadowTLS v2 relay,
  - added an app-level config/runtime proof for the same chain: `build_bridge -> runtime_outbounds().connect_io()` now carries `Shadowsocks -> detour=ShadowTLS(v1)` through a real Shadowsocks inbound and echo target using the same handshake-only relay semantics,
  - rebuilt the `interop-lab` ShadowTLS case around the same wrapper-chain semantics, added a dedicated handshake server to the topology, and verified matching Rust/Go outcomes in dual-kernel run `20260310T180117Z-a452c721-28f9-452d-954f-ceffe0e4e3e6`,
  - extended the remodel to inbound detour mode as well: runtime inbound late binding now exists, ShadowTLS inbound `version = 2` can unwrap into a chained Shadowsocks inbound, and `version = 3` now carries the full Go-compatible server-side config surface (`users`, `handshake`, `handshake_for_server_name`, `strict_mode`, `wildcard_sni`) alongside the new live-hook-based v3 outbound runtime.
  - `crates/sb-adapters/tests/shadowtls_inbound_e2e.rs` now also proves two previously open v3 branches:
    - `strict_mode=true` with a TLS1.2-only decoy falls back to raw TLS passthrough after authenticated client hello validation, bypassing detour dispatch,
    - `wildcard_sni=authed` with an unauthorized client falls back to the configured default `handshake` target instead of the wildcard target.
    - `handshake_for_server_name` with an unauthorized client still honors the matching custom SNI mapping instead of falling back to the default `handshake` target.
    - `wildcard_sni=all` with an unauthorized client now has a live ignored e2e as well: the local ShadowTLS inbound falls back to public `example.com:443` and returns a real HTTPS response.
  - `crates/sb-adapters/src/inbound/shadowtls.rs` now routes unauthorized v3 fallback through `PrefixStream` instead of the old `PrefixWriteStream`, fixing the direction of the buffered `client_hello` replay into the decoy handshake connection.
  - Remaining for actual ShadowTLS parity:
    - keep the Go-like v3 path stable when touching TLS dependencies: the authenticated `session_id` must stay inside the real rustls transcript, not be patched out of band,
    - `wildcard_sni=all` still lacks a fully local/offline runtime proof; the current evidence is an ignored live e2e because the test harness cannot bind the wildcard target on port 443 in this environment,
    - extend the new v3 path into interop-lab once we decide the next ShadowTLS evidence bump needs a dual-kernel case,
    - extend the same detour helper path to the next wrapper consumers only if the final ShadowTLS chain needs more than Trojan and Shadowsocks plain TCP.

## Rules for evidence updates

- Mark status as `established` only when there is fresh, reproducible evidence from the current code.
- Mark status as `partial` when evidence is single-kernel, sandbox-limited, or missing negative/recovery coverage.
- Mark status as `not established` when only config/smoke tests exist.
- Do not reuse old "production ready" wording unless the new evidence set actually supports it.
