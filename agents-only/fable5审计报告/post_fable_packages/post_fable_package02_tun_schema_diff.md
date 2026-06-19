<!-- tier: B -->
# post_fable_package02 — Go 1.13.13 TUN option diff record

Scope: schema/IR parity only (CAL-01 + H-4). **Not dataplane-ready** — `stack` and all
route/address semantics are stored, not executed; runtime mapping is package03 scope.
Code commit: `e3defcdf`.

## Sources

- Go field inventory: `go_fork_source/sing-box-1.13.13/option/tun.go:13-59`
  (`TunInboundOptions`), `option/tun_platform.go:5-14`, `option/inbound.go:51-59`
  (embedded `InboundOptions`; TUN does **not** embed `ListenOptions`).
- GUI emission: `GUI_fork_source/GUI.for.SingBox-1.19.0/frontend/src/utils/generator.ts:66-93`
  (TUN branch :81-90), `constant/profile.ts:113-123` (defaults).
- Rust support: `crates/sb-config/src/validator/v2/inbound.rs`
  (`TUN_ONLY_INBOUND_KEYS` + `lower_tun_options`), `crates/sb-config/src/ir/inbound.rs`
  (`TunOptionsIR`), `crates/sb-config/src/ir/raw.rs` (`RawTunOptionsIR`).

## GUI actually emits (default profile, TUN enabled)

`{type, tag, interface_name:"", address:[v4,v6], mtu:0, auto_route:true, strict_route:true,
endpoint_independent_nat:false, stack:"mixed"}`; `route_address`/`route_exclude_address`
only when non-empty. No listen block / sniff / platform on TUN.

## Field matrix (Go 1.13.13 json tag → status after package02)

| Go field | GUI emits | Rust schema | Rust IR | Notes |
|---|---|---|---|---|
| `interface_name` | yes (`""`) | accepted (tun-only) | yes | `""` normalized to unset; mirrored into legacy `name` as compat alias for runtime `TunInboundConfig.name` unless nested `tun.name` set |
| `address` | yes | accepted (tun-only) | yes | merged v4/v6 list kept verbatim; no split (package03) |
| `mtu` | yes (`0`) | accepted (tun-only) | yes | `0` normalized to unset (Go omitempty semantics) |
| `auto_route` | yes | accepted (tun-only) | yes | |
| `strict_route` | yes | accepted (tun-only) | yes | |
| `route_address` | conditional | accepted (tun-only) | yes | verbatim list |
| `route_exclude_address` | conditional | accepted (tun-only) | yes | verbatim list |
| `endpoint_independent_nat` | yes (`false`) | accepted (tun-only) | yes | Go 1.12 marks it Deprecated-removed (parse-only); stored, semantics-free |
| `stack` | yes (`mixed`) | accepted (tun-only) | yes | stored only; `mixed`/`system`/`gvisor` runtime mapping = package03 (CAL-10) |
| `inet4_address` / `inet6_address` | no | accepted (tun-only) | yes | deprecated Go aliases of `address`, kept for legacy configs |
| `iproute2_table_index` / `iproute2_rule_index` | no | rejected | no | not accepted; extend when needed |
| `auto_redirect` (+`_input_mark`/`_output_mark`) | no | nested-only / rejected flat | partial | `auto_redirect` exists in nested `TunOptionsIR`; marks not modeled |
| `loopback_address` | no | rejected | no | |
| `route_address_set` / `route_exclude_address_set` | no | rejected | no | |
| `include_interface` / `exclude_interface` | no | rejected | no | |
| `include_uid*` / `exclude_uid*` | no | rejected flat | partial | nested `exclude_uids` exists |
| `include_android_user` / `include_package` / `exclude_package` | no | rejected | no | |
| `udp_timeout` | no | nested-only | yes (nested) | also a generic InboundIR field |
| `platform` (TunPlatformOptions) | no | nested-only (string) | partial | nested `platform: Option<String>` only; HTTPProxyOptions not modeled |
| `gso` | no | rejected | no | Deprecated-removed in Go 1.12 |
| embedded `InboundOptions` (`sniff`/`domain_strategy`/`detour`/…) | no | accepted (generic) | yes (generic InboundIR) | deprecated in Go 1.12 |

## Precedence & normalization rules (locked by tests)

- Nested `tun {}` is the base; flat top-level fields overlay it — **flat wins**.
- Nested `tun {}` content is now validated through the strict `RawTunOptionsIR`
  bridge (deny_unknown_fields) — previously accepted unvalidated.
- Flat `mtu: 0` / `interface_name: ""` = unset (no override of nested values).
- TUN-only flat keys are rejected on non-TUN inbounds (per-type gating, net-new).

## H-4 probe result (beyond TUN, same GUI launch path)

GUI emits Go `ListenOptions` socket tuning fields on **every listen-type inbound**
(`generator.ts:77` listen-block spread): `tcp_fast_open`, `tcp_multi_path`,
`udp_fragment`. Strict schema rejected them → blocked the same GUI launch path as
CAL-01. Per package02's out-of-scope exception, they are now **accepted as
schema-valid no-ops** (not lowered into IR; GUI defaults are all `false`, which is
also a no-op in Go). Remaining H-4 surface (non-GUI-default fields, other inbound
types' optional fields) not systematically scanned — record-only, future package if
GUI E2E (package07) surfaces more.

Probe evidence: full GUI-shape config (mixed incl. listen block + default TUN)
passes `app run --check` end-to-end through the production strict pipeline.
