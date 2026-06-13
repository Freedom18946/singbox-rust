<!-- tier: B -->
# post_fable_package12_dns_schema_parity_gui_default

## Status

DONE (2026-06-13, code commit `349eecf3`). GUI default DNS schema/IR parity is
closed for the package07 F-1 blocker. This is DNS schema parity only; it does not
claim DNS dataplane, TUN dataplane, or full GUI readiness.

## Source Findings

- package07 F-1: GUI.for SingBox 1.19.0 default DNS uses Go 1.12 type-based DNS
  server fields that Rust strict validation rejected on the production load path.
- Blocking example: `domain_resolver` under `/dns/servers/*` made
  `./target/debug/app run --check -c <config>` exit before GUI could observe
  `sing-box started`.
- Scope was isolated to DNS server schema/IR parity: removing
  `domain_resolver`, `server_port`, `path`, and `interface` let the same shape
  progress.

## Objective

Make GUI default-ish DNS configs pass `config_from_raw_value`, `validate_v2`
strict mode, `to_ir_v1`, `app run --check`, and normal startup while preserving
strict unknown-field rejection.

## Implementation Contract

- Extend the DNS server allowlist only for known Go 1.12 / GUI fields:
  `domain_resolver`, `server_port`, `path`, and `interface`.
- Keep explicit legacy `address` as the highest-priority canonical source.
- Lower `domain_resolver` into `DnsServerIR.address_resolver`.
- Canonicalize type-based DNS server addresses:
  - `udp` -> `udp://host:port`
  - `tcp` -> `tcp://host:port`
  - `tls` / `dot` -> `tls://host:port`
  - `quic` / `doq` -> `quic://host:port`
  - `https` -> `https://host:port/path`
  - `h3` / `http3` / `doh3` -> `h3://host:port/path`
  - `dhcp` plus `interface` -> `dhcp://interface`
- Default DoH / DoH3 `path` to `/dns-query` when omitted; normalize a missing
  leading slash.
- Accept hosts-server `path` arrays and lower them into `hosts_path`, while
  preserving existing `hosts_path`.
- Preserve strict rejection for unknown DNS server fields such as
  `bogus_dns_server_field`.

## Out Of Scope

- DNS transport/dataplane redesign.
- TUN dataplane and GUI TUN runtime readiness.
- Broad Go DNS option rewrite or allow-any behavior.
- Raw DNS serde bridge expansion unless needed by the production load path.
- GUI or Go source changes.

## Acceptance Criteria

- GUI default DNS server shape passes strict validation.
- `domain_resolver` appears in IR as `address_resolver`.
- `server_port` and `path` appear in canonical addresses.
- `dhcp` plus `interface` validates and lowers.
- `hosts` plus `path` validates and lowers into `hosts_path`.
- Unknown DNS server fields still fail strict validation.
- Full GUI-default-ish DNS config passes `config_from_raw_value` and `app run
  --check`.

## Tests / Verification

- `git diff --check` -> PASS.
- `cargo test -p sb-config --lib pf12` -> 7 passed.
- `cargo test -p sb-config` -> PASS (lib 701 passed; integration/doc suites
  green, doc-tests 2 passed / 2 ignored).
- `cargo build -p app --bin app --features adapters,clash_api` -> PASS
  (existing `sb-core` unused warnings only).
- `./target/debug/app run --check -c /tmp/pf12-gui-default-dns.json` -> PASS.
- `./target/debug/app run --disable-color -c /tmp/pf12-gui-default-dns.json` ->
  PASS (`sing-box started`, then SIGINT clean shutdown).
- `WORK=/tmp/pf07-after-dns bash
  agents-only/fable5审计报告/post_fable_packages/post_fable_package07_probe_harness.sh`
  -> PASS (14/14).

## Docs To Update

- This package file.
- `agents-only/fable5审计报告/post_fable_packages/README.md`.
- `agents-only/active_context.md`, kept at or below 100 lines.

## Dependencies

- Depends on package07's F-1 finding.
- Package03 remains the next recommended high-goal package after this closure.

## Completion Notes

Completed 2026-06-13, code commit `349eecf3`
(`fix(sb-config): accept GUI DNS server schema fields`).

### What changed

- `crates/sb-config/src/validator/v2/dns.rs` now accepts the focused GUI/Go DNS
  server fields listed above and still rejects unrelated unknown fields.
- DNS lowering converts GUI type-based server shapes into canonical
  `DnsServerIR.address` values and maps `domain_resolver` into
  `address_resolver`.
- Hosts `path` arrays are preserved through `hosts_path`; DHCP `interface` is
  preserved through `dhcp://interface`.

### Boundary

F-1 is closed for DNS schema/IR parity. This does not make TUN dataplane-ready;
package03 remains the next recommended implementation package.
