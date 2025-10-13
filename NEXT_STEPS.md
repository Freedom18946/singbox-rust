Parity Roadmap (vs sing-box `dev-next`)

Last audited: 2025-10-12 22:10 UTC

## Current Snapshot
- **CLI entrypoint**: `app/src/main.rs` exposes only `check`, `auth`, `prom`, `run`, `route`, `version`; other parity commands live under `app/src/bin/*` as standalone executables.
- **Config surface**: `crates/sb-config/src/model.rs` + `crates/sb-config/src/inbound.rs` / `outbound.rs` recognise only HTTP/SOCKS/TUN inbounds and direct/block or limited V2Ray outbounds; top-level `log`, `dns`, `ntp`, `certificate`, `services`, and `experimental` sections are absent.
- **Protocol adapters**: Many adapters exist under `crates/sb-adapters/src/inbound` and `crates/sb-adapters/src/outbound`, but are unreachable because the loader (`app/src/config_loader.rs`) drops their configuration.
- **Geo / Rule-set tooling**: CLI binaries (`app/src/bin/geoip.rs`, `geosite.rs`, `ruleset.rs`) operate on loose files; there is no bundled dataset or compile/decompile parity.
- **Stubs**: WireGuard outbound (`crates/sb-core/src/outbound/wireguard_stub.rs`) returns `Unsupported`; AnyTLS/Tor have no implementation.

## Immediate Priorities (P0)
1. **Unify CLI** – Make a single `singbox` binary dispatch every upstream subcommand by embedding the existing bin logic (touch `app/src/main.rs`, `app/src/cli/mod.rs`, and move `app/src/bin/*` modules under the dispatcher).
2. **Full configuration schema** – Extend `sb-config` to parse upstream sections (`log`, `dns`, `ntp`, `certificate`, `endpoints`, `services`, `experimental`) and map the richer inbound/outbound variants into IR (`crates/sb-config/src/ir/mod.rs`) so `app/src/config_loader.rs` can instantiate adapters.
3. **Activate major protocol adapters** – Wire Shadowsocks/ShadowTLS/Trojan/VLESS/VMess/TUIC/Hysteria (inbound & outbound) through the expanded config, ensuring transport and multiplex options surface (`crates/sb-adapters/src/inbound`, `crates/sb-adapters/src/outbound`).
4. **Tooling parity** – Finish rule-set compile/decompile/upgrade flows and package GeoIP/Geosite databases with update hooks (`app/src/bin/ruleset.rs`, `app/src/bin/geoip.rs`, `app/src/bin/geosite.rs`, `crates/sb-core/src/router/ruleset`).
5. **Replace protocol stubs** – Implement WireGuard/Tor/AnyTLS outbounds (or document scope) and add conformance tests (`crates/sb-core/src/outbound/wireguard_stub.rs` and new modules).

## Near-term P1 Follow-ups
- Harden `check` command with schema-backed diagnostics and migration helpers (`app/src/bin/check.rs`).
- Introduce service support (DERP, resolved, ssm-api) once config scaffolding is ready (`crates/sb-core/src/service`, new).
- Provide packaging scripts for distributing geo databases and rule-sets alongside release artefacts (`scripts/`, CI).
- Add end-to-end tests comparing Rust CLI outputs with upstream binaries across representative configs (`tests/`).

## Verification Plan
- Extend `sb-config` unit tests to cover each new schema block and protocol permutation.
- Build integration fixtures that run `app` vs upstream `sing-box` for every inbound/outbound combination and compare exit codes/outputs.
- Exercise GeoIP/Geosite/Rule-set commands on sample datasets to confirm identical CLI behaviour.
- Gate releases on `cargo test --workspace --all-features` plus a parity smoke script invoking the unified CLI.
