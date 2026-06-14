<!-- tier: B -->
# post_fable_package08 — Long-tail outbound & subscription evidence

> HEAD at work start `85bc6706`. Local-only verification (GitHub Actions stay
> disabled). This note is the evidence backing the package08 closure; it does not
> duplicate volatile state (see `agents-only/active_context.md`).

Scope reminder: this package **clarifies** long-tail status, **decides** the trojan
ignored-test question, and **pins** subscription parser behavior with fixtures. It is
NOT full-protocol parity certification, and it does not change feature aggregates.

---

## CAL-18 — long-tail outbound status (calibrated against current main)

Key correction to the audit: the four "stub" outbounds (dns/tor/tailscale/
shadowsocksr) all have **real connector implementations**. The `None`/"stub" only
exists in the `#[cfg(not(feature = ...))]` branch compiled when the matching Cargo
feature is OFF. The real defect was the *feature-OFF* path: it returned `None`, which
`sb-core` bridge (`adapter/bridge.rs`, "no outbound builder available for requested
kind") logged generically and skipped — surfacing downstream as a misleading
"outbound not found", with no feature name or next step.

### Inventory matrix

| config type | sb-adapters feature | app feature | in `adapters`? | in `parity`? | feature-OFF behavior (after this package) | real connector |
|---|---|---|---|---|---|---|
| **dns** | `adapter-dns` | `adapter-dns` | **YES** | **YES** | n/a — real in parity (locked by test) | `outbound/dns.rs` `DnsConnector` |
| **tor** | `adapter-tor` (pulls `arti-client`, ~32 tor-* crates + native-tls) | `adapter-tor` (standalone, NOT in `adapters`) | NO | NO | **loud** `InvalidConfigConnector` (type+feature+rebuild) | `outbound/tor.rs` `TorOutbound` |
| **tailscale** | `adapter-tailscale` | (none) | NO | NO | **loud** `InvalidConfigConnector` | `outbound/tailscale.rs` `TailscaleConnector` |
| **shadowsocksr** | `legacy_shadowsocksr` | (none) | NO | NO | **loud** `InvalidConfigConnector` | `outbound/shadowsocksr/` |
| hysteria2 / tuic / shadowtls / anytls / ssh (control) | `adapter-*` | `adapter-*` | YES | YES | real in parity | `outbound/*.rs` |

Notes:
- `dns` outbound's `connect()` deliberately errors for generic TCP ("use it for DNS
  resolution only") — that is by-design, not a stub.
- `tor` is correctly kept out of `adapters`/`parity`: enabling it drags arti + a
  second (native-tls) TLS stack and bootstraps a full embedded Tor client at runtime.

### Decision (user-selected: "Loud error + keep current state")

- No change to feature aggregates; no new app features; arti et al. stay opt-in.
- Feature-OFF stub branches for tor/tailscale/shadowsocksr now return
  `invalid_config_outbound(kind, unsupported_outbound_feature_reason(feature))`
  instead of `stub_outbound(kind); None`. Dialing such an outbound now fails loudly
  with: `<type> outbound is disabled due to invalid config: this long-tail protocol
  is not compiled into this binary; it requires the '<feature>' cargo feature
  (excluded from the default/parity build). Rebuild with that feature enabled (e.g.
  --features <feature>) or remove this outbound from the config`.
- Reuses the existing `InvalidConfigConnector` + `invalid_config_outbound`
  (`register.rs`); the new helper is `unsupported_outbound_feature_reason`.
- `dns` is left as-is (real); a regression guard test confirms it is not a stub.

Edits: `crates/sb-adapters/src/register.rs` — new `unsupported_outbound_feature_reason`
helper; tor / tailscale / shadowsocksr feature-OFF branches; 3 new `longtail_*` tests.

---

## CAL-28 — trojan ignored-test decision

The two cited ignored tests' obstacles were already solved by the in-file harness
`fresh13_tls_verifier_loopback` (self-signed loopback TLS listener + `init_crypto`).
Decision: **enable/rewrite**, not keep manual.

| former test | decision | rationale |
|---|---|---|
| `test_trojan_connection_to_mock_server` (`#[ignore]` "requires actual TLS server") | **enabled** → rewritten as `connection_to_mock_tls_server_completes_handshake` | the loopback harness IS that server; asserts a real TCP+TLS handshake (no connection-refused, no cert-verify error). Was a no-op placeholder before. |
| `test_trojan_connection_timeout` (`#[ignore]` "CryptoProvider may not be available") | **enabled** → rewritten as `connection_to_unroutable_ip_fails_bounded` | misdiagnosis: timeout fires in the TCP connect phase, before TLS/CryptoProvider. Calls `init_crypto()` anyway; asserts bounded failure. |
| (new) `trojan_udp_roundtrip_ipv4/ipv6/domain`, `trojan_udp_encode_rejects_overlong_domain`, `trojan_udp_decode_rejects_malformed` | **added** (pure local) | `TrojanUdpSocket::encode_packet`/`decode_packet` had zero unit coverage; covers all ATYP branches + error classification offline. |
| `app/tests/trojan_protocol_validation_test.rs` 1000-handshake / 100-concurrent, `performance_validation.rs` trojan benches | **kept manual** | performance/scale class (run with `--ignored`); a different category from CAL-28's "deepest connection/timeout" tests. |

Result: `tests/trojan_integration.rs` now runs **19 tests, 0 ignored** (was 17 + 2
ignored). Edits: `crates/sb-adapters/tests/trojan_integration.rs` (two rewrites moved
into the harness module + a top-of-file pointer note); `crates/sb-adapters/src/
outbound/trojan.rs` mod tests (5 UDP tests).

---

## H-10 — subscription fixture regression set

owner = `sb-subscribe` (the "Subscription Processing Engine"). New static fixtures
under `crates/sb-subscribe/tests/fixtures/` + `tests/subscription_fixtures.rs`
(`include_str!`, no network). Note: `sb-config::subscribe` is a separate, narrower
second parser (used by app to build a runtime `Config`); it is not H-10's owner.

| format | entry | fixture | what is pinned |
|---|---|---|---|
| Clash YAML | `parse_clash::parse` | `clash_basic.yaml` (trojan/vmess/vless/ss + unknown `brook`) | known types kept as `kind`; **unknown type passed through verbatim** (baseline) |
| sing-box JSON | `parse_singbox::parse` | `singbox_basic.json` (trojan/vmess/ss/direct/selector + route rules) | `name:kind` preserved incl. `selector`; route.rules expand to DSL |
| URI-line | `provider_parse::parse_proxy_content` | `provider_uris.txt` (trojan/vless/hy2/vmess(b64)/ss(b64) + `tuic://` + 1 malformed) | 5 known parse; **`tuic://` + malformed silently DROPPED** → len shrinks to 5 |
| URI-line JSON-array | same | inline `[{"ty":"unknown_xyz"}]` | closed enum → **`Err`** (the one path that rejects unknown loudly) |

Audit's core concern ("is unknown silently treated as success?") is now an explicit
baseline: Clash/sing-box silently pass unknown types through; the URI text path
silently drops unknown schemes; only the JSON-array path errors. Result: 4 tests pass.

---

## Verification (all local, all PASS)

- `cargo test -p sb-adapters --lib longtail` (default) + `--features adapter-dns` → 2 / 3 pass
- `cargo test -p sb-adapters --test trojan_integration --features "adapter-trojan,adapter-shadowsocks"` → **19 pass, 0 ignored**
- `cargo test -p sb-adapters --lib trojan_udp --features "adapter-trojan,adapter-shadowsocks"` → 5 pass
- `cargo test -p sb-subscribe --all-features` → all pass (incl. 4 fixtures)
- `cargo test -p sb-config --lib subscribe` → 2 pass
- `cargo check -p app --features "adapters,clash_api"` / `--features parity` → Finished
- `cargo check --workspace --all-features` → Finished (1 pre-existing warning, below)
- `git diff --check` → clean

### Command correction

The task/plan command `cargo test -p sb-adapters --lib trojan --features "adapter-trojan trojan"`
**does not compile**: `adapter-trojan` inbound (`inbound/trojan.rs`) unconditionally
calls `crate::inbound::shadowsocks::parse_ss_addr`, but the `shadowsocks` module is
feature-gated and `adapter-trojan` does not declare that dependency. Equivalent
compilable set used: `--features "adapter-trojan,adapter-shadowsocks"` (the latter
pulls `shadowsocks`). The two target trojan tests live in the integration target,
so they are exercised via `--test trojan_integration`, and the UDP unit tests via
`--lib trojan_udp`.

---

## Follow-ups registered (out of package08 scope)

1. **`adapter-trojan` missing `shadowsocks` feature dependency** (pre-existing,
   inbound). `inbound/trojan.rs` uses `inbound::shadowsocks::parse_ss_addr`
   unconditionally; `adapter-trojan` should declare `shadowsocks` (or gate the call).
   Candidate for package09 (lint/test/gate) — a feature-wiring defect, not dataplane.
2. **trojan `dial` ignores `DialOpts`** (`_opts`); connect timeout derives from
   `config.connect_timeout_sec.unwrap_or(30)`. Observed wall-time to a non-routable IP
   is ~10s (not the config's 2s), suggesting a transport-dialer-internal timeout.
   Dataplane connect-timeout follow-up — not in package08.
3. **Clash/sing-box parsers silently pass unknown proxy types through**, and there is
   **no skip/unknown counter returned to the caller** (`MergeStats.skipped_unknown`
   exists but is a discarded local `_stats`; `Profile` has no stat field). Surfacing a
   per-parse skip count is a subscription-observability enhancement; the public
   capability-ledger wording is a **package11 doc-calibration follow-up**.
4. **Pre-existing dead-code warning** `subscribe_runtime_state` at
   `app/src/run_engine_runtime/admin_start.rs:194` (introduced by `cf1de32b`,
   package06) — surfaced by `cargo check --workspace --all-features`, unrelated to
   package08.

---

## 08b acceptance fix (2026-06-14)

Two acceptance-review nits closed; no behavior / feature-aggregate change:

1. **longtail test `unused_imports` warning.** `cargo test -p sb-adapters --lib longtail`
   on the default feature set emitted `unused imports: OutboundIR and OutboundType`
   (`register.rs` test module). The top-level `use sb_config::ir::{OutboundIR,
   OutboundType};` is consumed only by feature-gated tests; confirmed (via rg) those
   tests span **four** features — `adapter-dns`, `adapter-wireguard-outbound`,
   `adapter-shadowtls`, `adapter-vless` — not just `adapter-dns`. The import now carries
   `#[cfg(any(...four...))]`, so the default (no-adapter) build does not compile it (no
   warning) while every feature build still has it. A bare `adapter-dns` cfg would have
   broken the wireguard-outbound / shadowtls / vless tests.
2. **active_context stale number.** `Current Build And Gate` still read
   `trojan_integration: 17 PASS, 2 ign`; corrected to `19 PASS, 0 ignored` to match the
   package08 closure.

Verified: `cargo test -p sb-adapters --lib longtail` (no warning) + `--features
adapter-dns` (3 pass) + `--test trojan_integration --features
adapter-trojan,adapter-shadowsocks` (19 pass / 0 ignored) + `git diff --check` clean.
Commits: `fix(adapters): remove longtail test cfg warning` + `checkpoint: record
package08 acceptance fix`.
