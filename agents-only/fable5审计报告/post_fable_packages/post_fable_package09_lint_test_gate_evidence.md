<!-- tier: B -->
# post_fable_package09 — lint / test / feature-gate evidence

> HEAD at work start `8211366b` (package08 + 08b closed). Local-only verification
> (GitHub Actions stay disabled). Backs the package09 closure; does not duplicate
> volatile state (see `agents-only/active_context.md`).

Scope: CAL-08 / CAL-19 / CAL-27 / CAL-29 + the two package08 follow-ups. No protocol
rewrites, no GitHub Actions, no broad lint enforcement.

---

## CAL-19 — selector / proxy-pool test rot (DONE)

- Rewrote `crates/sb-core/tests/proxy_pool_select.rs` against the current `PoolSelector`
  API (`sb_core::outbound::selector`). Removed the always-false
  `#![cfg(not(any(feature = "router", not(feature = "router"))))]`, the 4
  `#[ignore = "PoolSelector API changed, needs rewrite"]` markers, and the local
  `MockHealthView`. 5 active tests: populated-pool select+healthy, unhealthy filtering,
  lowest-RTT preference, no-healthy → `None`, pool bookkeeping + unknown pool.
- **De-scoped (recorded)**: the former `weighted_selection` and `sticky_affinity` tests are
  NOT reinstated — the current `PoolSelector::select` ignores weight/sticky (delegates to
  `select_healthy_endpoint`: healthy filter + min `avg_rtt_ms`, `selector.rs:454-463`).
  Endpoint addresses use `http://IP:PORT` (the only form `ProxyEndpoint::parse` accepts,
  `endpoint.rs:21`); an explicit endpoint-count assertion guards against silent parse drops.
- Deleted the 3-line stubs `selector_p2.rs` + `selector_smoke.rs` (`git rm`). Coverage folds
  into `proxy_pool_select.rs`; replacement command `cargo test -p sb-core --test proxy_pool_select`.
- Result: 5 passed. `rg "PoolSelector API changed"` + the always-false cfg → no hit in selector tests.
- Out-of-scope note: 5 OTHER sb-core integration tests still carry the same always-false cfg
  (`dns_cache_basic`, `dns_cache_stale_coalesce`, `prop_socks5_udp`, `prop_net_coverage`,
  `router_domain`) — pre-existing rot, NOT CAL-19's named set; logged for future review.

## package08 follow-up #1 — trojan inbound feature gate (DONE, supersedes follow-up #1)

- `crates/sb-adapters/src/inbound/trojan.rs:614` (`parse_trojan_request`, a fuzz/test helper)
  unconditionally calls `inbound::shadowsocks::parse_ss_addr`; the `shadowsocks` module is
  `#[cfg(feature = "shadowsocks")]` (`inbound/mod.rs:52`). The compile-break trigger is the
  inbound **`trojan` feature** (`Cargo.toml:138`), NOT outbound `adapter-trojan`.
- Fix: the `trojan` feature now declares `"shadowsocks"` (1-line + comment). Minimal — it does
  not pull the heavier `adapter-shadowsocks`.
- Evidence: `cargo test -p sb-adapters --lib trojan --features "adapter-trojan,trojan"` →
  23 passed (the command package08 recorded as non-compiling). No need to add
  `adapter-shadowsocks` for trojan lib tests anymore.

## package08 follow-up #2 — trojan dial DialOpts timeout (DONE, supersedes follow-up #2)

- `outbound/trojan.rs:447` `dial` ignored `_opts`; the connect timeout was
  `config.connect_timeout_sec.unwrap_or(30)`. Now
  `_opts.connect_timeout.min(config_timeout)` (decision D1 — stricter of the two; the single
  `timeout` var feeds the detour / dialer / fallback paths). `_opts` keeps its underscore name
  (the feature-off dial arm does not use it; reading `_opts.connect_timeout` is legal and
  warning-free).
- `udp_relay_dial` (`trojan.rs:313`, signature `(&self, target)`, no `DialOpts` param) is a
  separate helper — left as-is (still config-derived) to avoid scope creep; registered as a follow-up.
- Lock test `dial_honors_short_dialopts_connect_timeout` (`trojan_integration.rs`): config
  ceiling 99s + 250ms DialOpts → assert the `AdapterError::Timeout` does NOT report `99s`. The
  error-content assertion is deterministic — the reported duration is the internal 250ms
  `timeout` var regardless of scheduler jitter — plus a 40s test-side guard against a
  regression hanging ~99s.
- **Observation (not a trojan bug)**: under `--features adapter-trojan,trojan`, `sb-transport`
  IS enabled, so dial uses the dialer path. Under cargo-test parallel saturation, the
  `tokio::time::timeout` wall-clock occasionally stretches to ~10s (tokio timer starvation,
  reproduced in 2 of 3 consecutive runs) instead of 250ms — which is exactly why the assertion
  is wall-clock-independent. Result: trojan_integration 20 passed, stable across 3 runs.

## CAL-08 — lint policy inventory (DONE: inventory/decision closed, enforcement deferred)

Decision D2: inventory + rollout recommendation only; **zero `[lints]` changes**. Broad
enforcement needs user approval (per the package dependency).

- workspace `Cargo.toml:54-57` declares `clippy::unwrap_used/expect_used/panic/
  undocumented_unsafe_blocks = deny`, but only crates with `[lints] workspace = true` inherit
  it — that is **sb-tls alone** (`sb-tls/Cargo.toml:76`). Others rely on scattered crate-level
  inner attrs: sb-admin-contract / sb-metrics / sb-platform / sb-security `#![deny(...)]`; app
  only `#![warn(...)]`; sb-core / sb-config / sb-adapters / sb-transport / sb-api / sb-subscribe
  / sb-types / sb-proto / sb-common / sb-runtime have none.
- Per-crate raw `src/` counts (include inline `#[cfg(test)]`, so they overstate production exposure):

  | crate | unwrap | expect | panic | cfg(test) | enforced |
  |---|---:|---:|---:|---:|---|
  | sb-core | 684 | 257 | 65 | 160 | no |
  | sb-config | 456 | 86 | 0 | 41 | no |
  | sb-adapters | 255 | 297 | 8 | 54 | no |
  | sb-tls | 183 | 22 | 13 | 17 | **yes (workspace)** |
  | app | 101 | 112 | 18 | 69 | warn-only |
  | sb-transport | 95 | 6 | 14 | 23 | no |
  | sb-api | 52 | 0 | 3 | 4 | no |
  | sb-metrics | 41 | 2 | 0 | 3 | **yes (inner)** |
  | sb-subscribe | 12 | 0 | 0 | 3 | no |
  | sb-common | 10 | 0 | 1 | 9 | no |
  | sb-runtime | 3 | 0 | 0 | 5 | no |
  | sb-types | 3 | 0 | 1 | 4 | no |
  | sb-platform | 2 | 4 | 2 | 18 | **yes (inner)** |
  | sb-proto | 0 | 0 | 0 | 0 | no |
  | sb-security | 0 | 1 | 0 | 3 | **yes (inner)** |
  | sb-admin-contract | 0 | 0 | 0 | 1 | **yes (inner)** |

- clippy command-line probe (no Cargo.toml change), `-W clippy::unwrap_used -W expect_used
  -W panic`: `sb-proto` and `sb-runtime` both show **0** warnings → zero-cost enable candidates.
- Constraint: `clippy.toml` has **no `allow-unwrap-in-tests`**, so enabling deny would also flag
  test-module unwraps. A rollout must add that key or accept test churn.
- Recommended rollout (deferred, needs approval): sb-proto + sb-runtime (zero cost) →
  sb-types / sb-subscribe / sb-common (≤12 each) → set `allow-unwrap-in-tests` → big crates last
  (sb-core / sb-config / sb-adapters / sb-transport / sb-api / app).

## CAL-27 — warnings recheck + fix (DONE: clippy --all-features --all-targets back to 0)

- Re-measured against current main (NOT copied from RD-07; package05/06/08 changed code). RD-07's
  old pair (`supervisor.rs:2002` unused import, `v2ray_api.rs:987` dead `current_generation`) is
  **gone** under all-features.
- `cargo clippy --workspace --all-features --all-targets` initially showed **5** warnings; all
  fixed → **0**:
  1. `admin_start.rs:193` doc_markdown `V2Ray` → backtick (**introduced by this package's own new
     doc comment** — fixed).
  2. `admin_start.rs:194` `subscribe_runtime_state` dead-code (package06; only the `#[cfg(test)]`
     `immediate_shutdown` test consumes it) → `#[cfg_attr(not(test), allow(dead_code))]` + comment
     (symmetric to V2Ray's production-consumed version; kept as GUI/sidecar observability hook).
  3. `output.rs:99` redundant_pub_crate on `STARTUP_KEYWORD` (used only within output.rs at
     `:102/:106`) → drop `pub(crate)`.
  4. `sidecar_runtime.rs:313` missing_const_for_fn → `const fn` (compiles on msrv 1.92).
  5. `supervisor.rs:2431/:2497` (test code) `io::Error::new(ErrorKind::Other, _)` →
     `io::Error::other(_)`.
  Items 3-5 were pre-existing low-risk (package01/06 + test code), fixed here so the gate is truly
  0 — the lint-discipline goal of this package. All mechanical, no behavior change.
- Per-target recheck (each 0 warning): `cargo test -p sb-core --lib` / `-p sb-adapters --lib
  longtail` / `-p app --lib --features adapters,clash_api,v2ray_api` / `cargo check --workspace
  --all-features`.

## CAL-29 — flake handling (DONE: 1 hardened, rest documented)

| flake | root cause | handling | isolation |
|---|---|---|---|
| `cache_file::test_fakeip_persistence_sled` | sled dir-lock + debouncer worker + reopen ordering | **hardened**: explicit `drop(writer)` before reopen (sled drop-flush + worker join). 6 consecutive default-concurrency runs green | `cargo test -p sb-core --lib services::cache_file -- --test-threads=1` |
| `dns_steady::bad_domain_returns_err` | system resolver NXDOMAIN-hijack | documented (no in-process fix without a mock resolver) | clean network; `--test-threads=1` |
| `dns_steady::udp_pool_timeout_is_handled` | process-global `SB_DNS_POOL` env race across test binaries | documented (in-file `serial_guard` is per-file) | `--test-threads=1` |

- **Newly found, same class (logged, NOT in CAL-29's set)**: `app
  outbound_builder::simple::simple_proxy_family_skips_unresolvable_host_or_missing_endpoint`
  asserts `invalid.invalid.invalid` is NXDOMAIN. On the current (hijacking) network it resolves
  to `198.18.2.39` (verified via `getaddrinfo`), so `build_simple_outbound` returns `Some` and the
  assertion flips. Same resolver-hijack class as `dns_steady::bad_domain`; environmental, NOT a
  package09 regression; a one-line flake note was added; passes on a clean network.

## Test / gate results

| command | result |
|---|---|
| `cargo test -p sb-core --test proxy_pool_select` | 5 passed |
| `cargo test -p sb-core --lib` | 570 passed, 9 ignored |
| `cargo test -p sb-core --test dns_steady -- --test-threads=1` | 3 passed |
| `cargo test -p sb-core --lib fakeip_persistence_sled -- --test-threads=1` | 1 passed |
| `cargo test -p sb-adapters --lib trojan --features adapter-trojan,trojan` | 23 passed |
| `cargo test -p sb-adapters --test trojan_integration --features adapter-trojan,trojan` | 20 passed (×3 stable) |
| `cargo test -p sb-adapters --lib longtail` | 2 passed |
| `cargo test -p app --lib --features adapters,clash_api,v2ray_api` | 182 passed, 1 env-flake (above) |
| `cargo check --workspace --all-features` | 0 warning |
| `cargo clippy --workspace --all-features --all-targets` | 0 warning |
| `git diff --check` | clean |

## Follow-ups (not in package09 scope)

1. Lint enforcement rollout (CAL-08) — deferred, needs user approval; start with sb-proto/sb-runtime.
2. 5 other always-false-cfg sb-core integration tests (dns_cache / prop / router_domain) — pre-existing rot, future review.
3. `app outbound_builder::simple` resolver-hijack flake + the `dns_steady` pair — true hardening needs mock-resolver injection (out of minimal scope).
4. trojan `udp_relay_dial` still derives connect timeout from config only (no `DialOpts` param) — wire if the UDP path gains opts.
