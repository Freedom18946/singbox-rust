<!-- tier: S -->
# Active Context

> Purpose: high-frequency project navigation. S-tier: read every
> session.
> Discipline: keep only current-stage facts. This file must stay
> under 300 lines.
> **This file is the single source of truth for volatile state**
> (phase, parity-BHV, build/gate). Other docs point here, not copy.

---

## Resume (2026-07-03) - app sb-bench input audit cleanup

- **`app/src/bin/sb-bench.rs` audit cleanup DONE locally**: invalid `SB_BENCH_TCP`,
  `SB_BENCH_UDP`, `SB_BENCH_DNS`, and `SB_BENCH_DNS_NAME` inputs now return structured errors
  instead of panicking through `expect`.
- **Bench runtime hygiene tightened**: benchmark helpers now propagate setup errors, JSON
  serialization and histogram creation use `Result`, and per-sample UDP/DNS socket/encoding
  failures no longer crash spawned tasks.
- **Test coverage tightened**: focused `sb-bench` binary tests cover all invalid target/name
  input paths; a real CLI run with invalid `SB_BENCH_TCP` exits non-zero with an actionable
  error and no panic.
- **Verification PASS**: app fmt, focused `sb-bench` tests, app all-target/all-feature check,
  strict app clippy, real invalid-env CLI check, residual scan, and `git diff --check`.
- **Scope note**: app benchmark CLI hygiene only. No REALITY closure, dual-kernel BHV/parity
  movement, release packaging completion, or workflow automation is claimed.

## Resume (2026-07-03) - app generate TLS keypair audit cleanup

- **`app generate tls-keypair --days` audit cleanup DONE locally**: the CLI now builds explicit
  `rcgen::CertificateParams` so `--days` controls the self-signed certificate validity window
  instead of being accepted and ignored.
- **Input contract tightened**: `--days 0` is rejected with a structured error, and the app
  dependency graph now treats `time` as a production dependency for certificate validity math.
- **Test coverage tightened**: focused generate CLI tests cover the validity-window duration and
  zero-day rejection path without adding new residual `expect`/`panic!` scan noise.
- **Verification PASS**: app fmt, focused TLS keypair tests, app all-target/all-feature check,
  strict app clippy, residual scan, and `git diff --check`.
- **Scope note**: app key-generation CLI hygiene only. No REALITY closure, dual-kernel BHV/parity
  movement, release packaging completion, or workflow automation is claimed.

## Resume (2026-07-03) - app preflight CLI audit cleanup

- **`app/src/bin/preflight.rs` audit cleanup DONE locally**: preflight now fails explicitly on
  missing config files and invalid JSON instead of silently substituting `{}` and reporting a
  successful preflight contract.
- **Test coverage tightened**: new `preflight_cli` integration tests cover valid output,
  missing-file failure, and invalid-JSON failure; the test is registered behind the same
  `router` feature gate as the preflight binary.
- **Verification PASS**: app fmt, focused preflight CLI test, app all-target/all-feature check,
  strict app clippy, residual scan, and `git diff --check`.
- **Scope note**: app preflight CLI hygiene only. No REALITY closure, dual-kernel BHV/parity
  movement, release packaging completion, or workflow automation is claimed.

## Resume (2026-07-03) - app subs CLI audit cleanup

- **`app/src/bin/subs.rs` audit cleanup DONE locally**: subscription merge/diff CLI now returns
  structured errors for read/parse/write failures instead of panicking through `expect`/`unwrap`.
- **Test coverage tightened**: `subs_merge_diff` now covers invalid JSON failure output and
  asserts the CLI reports a parse error without a panic; existing merge/diff success coverage
  was converted to fallible assertions without path/string unwraps.
- **Verification PASS**: app fmt, focused `subs_merge_diff` test, app all-target/all-feature
  check, strict app clippy, residual scan, and `git diff --check`.
- **Scope note**: app subscription CLI hygiene only. No REALITY closure, dual-kernel BHV/parity
  movement, release packaging completion, or workflow automation is claimed.

## Resume (2026-07-03) - app prefetch audit cleanup

- **`app` prefetch CLI audit cleanup DONE locally**: prefetch stats/watch output now includes
  total fetched bytes and session duration instead of collecting those counters silently.
- **Test coverage tightened**: focused prefetch tests now assert byte/duration totals in both
  JSON and text output builders, and the prior all-feature `app` dead-code warning is gone.
- **App strict gate unblocked**: `app --all-features` strict clippy exposed a SOCKS UDP helper
  argument-list lint in the adapter dependency; the reverse-relay inputs are now wrapped in an
  internal task struct with focused SOCKS UDP checks passing.
- **Verification PASS**: app fmt/check, focused prefetch tests, strict app clippy, sb-adapters
  fmt/check, focused SOCKS UDP tests, residual scan, and `git diff --check`.
- **Scope note**: app CLI/audit hygiene plus app-gate adapter lint only. No REALITY closure,
  dual-kernel BHV/parity movement, release packaging completion, or workflow automation is claimed.

## Resume (2026-07-03) - sb-types audit cleanup

- **`crates/sb-types` audit cleanup DONE locally**: crate metadata now inherits the workspace
  license/repository, test-only `serde_json` moved to dev-dependencies, and crate docs no longer
  claim zero dependencies while `serde`/`thiserror` remain intentional contract dependencies.
- **Opaque stream contract tightened**: `BoxedStream` docs no longer describe a placeholder, and
  the marker trait has a blanket `Send + Sync + 'static` impl with a regression test proving
  opaque stream tokens can be boxed without adding runtime/async dependencies.
- **HTTP response contract tightened**: `HttpResponse` now offers normalized response-header
  construction/insertion, keeps case-insensitive direct-field compatibility, and the reqwest
  app adapter uses that contract. sb-types test scan noise (`unwrap`/`panic`/dummy fixtures)
  was removed.
- **Verification PASS**: sb-types/app fmt, sb-types all-target/all-feature check, unit tests,
  doctests, strict clippy, normal dependency-tree review, clean residual audit scan,
  `git diff --check`, and app all-target/all-feature check (existing prefetch warnings only).
- **Scope note**: sb-types contract hygiene only. No REALITY closure, dual-kernel BHV/parity
  movement, release packaging completion, or workflow automation is claimed.

## Resume (2026-07-02) - sb-test-utils audit cleanup

- **`crates/sb-test-utils` audit cleanup DONE locally**: stale crate-level docs now match
  the actual exported helpers, and the redundant `tokio/full` dev-dependency was removed.
- **SOCKS5 mock hygiene tightened**: unsupported TCP request paths return protocol failure
  replies, RSV is validated, background handshake errors no longer print noisy diagnostics,
  and fixed 60-second association sleeps were replaced by connection EOF handling.
- **Compatibility documented and tested**: legacy UDP relay reply shape is explicit and
  covered by regression tests alongside unsupported-command and invalid-RSV cases.
- **Verification PASS**: sb-test-utils fmt/check/tests/doctests/strict clippy, focused
  sb-core SOCKS5/UDP caller tests, residual audit scan, and `git diff --check`.
- **Scope note**: sb-test-utils audit/test hygiene only. No REALITY closure, dual-kernel
  BHV/parity movement, release packaging completion, or workflow automation is claimed.

## Resume (2026-07-02) - sb-subscribe audit cleanup

- **`crates/sb-subscribe` audit cleanup DONE locally**: Clash `MATCH` and sing-box
  `route.final` now survive subscription parsing as `default=...` DSL lines instead of
  being dropped from the generated profile.
- **Output/provider hygiene tightened**: view/diff/preview JSON now escapes dynamic object
  keys and unknown plan kinds via structured JSON builders; ruleset provider cache now
  expands cached text/base64 bodies instead of returning a placeholder expansion.
- **Test hygiene DONE locally**: empty compile-only shape test was replaced with assertions,
  schema fixture failures return structured test errors, and new regression tests cover
  default-route preservation, JSON escaping, and provider cache hit/miss behavior.
- **Verification PASS**: sb-subscribe fmt, no-default/all-features checks, all-target tests,
  doctests, strict clippy, residual audit scan, and `git diff --check`.
- **Scope note**: sb-subscribe audit/test hygiene only. No REALITY closure, dual-kernel
  BHV/parity movement, release packaging completion, or workflow automation is claimed.

## Resume (2026-07-02) - sb-security audit cleanup

- **`crates/sb-security` audit cleanup DONE locally**: token/credential redaction now
  counts Unicode chars instead of bytes, fully masks very short tokens, and avoids the
  prior short-Unicode leakage / emoji underflow panic class.
- **Secret-source policy tightened**: env fallbacks are treated as development-only inline
  configuration, rejected by the default secure loader, and marked insecure when explicitly
  allowed; unsupported pattern validators now fail instead of silently accepting input.
- **Verification PASS**: sb-security fmt, no-default/all-features checks, all-target tests,
  doctests, strict clippy, residual audit scan, and `git diff --check`.
- **Scope note**: sb-security audit/test hygiene only. No REALITY closure, dual-kernel
  BHV/parity movement, release packaging completion, or workflow automation is claimed.

## Resume (2026-07-02) - sb-runtime audit cleanup

- **`crates/sb-runtime` audit cleanup DONE locally**: offline Trojan/VMess alpha handshakes
  now encode host length as `u16le` with bounded host bytes, avoiding previous `u8`
  truncation for hosts longer than 255 bytes.
- **Test/runtime hygiene DONE locally**: JSONL streaming skips blank lines without fake
  zero-length frames while returning parse failures; replay files use isolated `tempfile`
  directories; golden/debug/placeholder/dead-code remnants were removed or clarified.
- **Verification PASS**: sb-runtime fmt, no-default/all-features checks, all-target tests,
  doctests, strict clippy, residual debug/placeholder scan, and `git diff --check`.
- **Scope note**: sb-runtime audit/test hygiene only. No REALITY closure, dual-kernel
  BHV/parity movement, release packaging completion, or workflow automation is claimed.

## Resume (2026-07-02) - sb-platform audit cleanup

- **`crates/sb-platform` audit cleanup DONE locally**: Android process matching now
  compiles through procfs without the unwired JNI placeholder, Windows API feature gates
  cover the actual Win32 calls, and OS detection includes Android.
- **Platform behavior calibrated**: Linux network monitor callbacks emit change events from
  netlink polling, system proxy command failures are propagated instead of being silently
  accepted, WinInet/env proxy handling recognizes SOCKS `ALL_PROXY` and PAC settings, and
  Windows TUN now fails explicitly instead of exposing a fake active adapter.
- **Verification PASS**: sb-platform fmt/check/test/clippy for all-features and no-default
  paths; doctests; locked check; Linux/Windows/Android target check + clippy; residual
  debug/placeholder scan; `git diff --check`.
- **Scope note**: sb-platform audit/test hygiene only. No REALITY closure, dual-kernel
  BHV/parity movement, release packaging completion, or workflow automation is claimed.

## Resume (2026-07-02) - sb-metrics audit cleanup

- **`crates/sb-metrics` audit cleanup DONE locally**: unused direct deps were removed,
  stale/debug-style comments and the short-lived metrics example were cleaned, HTTP request
  duration buckets now use real millisecond bounds, and selector failover labels are admitted
  before metric registration.
- **Staged-surface docs calibrated**: cardinality, transfer, SOCKS, and HTTP helper modules now
  state explicit-call / compatibility scope instead of implying automatic workspace-wide wiring.
- **Verification PASS**: `cargo fmt -p sb-metrics --check`, `cargo check -p sb-metrics
  --all-targets --offline`, `cargo test -p sb-metrics --all-targets --offline`,
  `cargo clippy -p sb-metrics --all-targets --all-features --offline -- -D warnings`,
  `cargo check -p sb-metrics --all-targets --locked`, sb-metrics doctests, residual audit scan,
  and `git diff --check`.
- **Scope note**: sb-metrics audit/test hygiene only. No REALITY closure, dual-kernel
  BHV/parity movement, release packaging completion, or workflow automation is claimed.

## Resume (2026-07-02) - sb-core audit cleanup

- **`crates/sb-core` audit cleanup DONE locally**: router hot-cache registration now
  stores the hot source independently, so `register_router_hot_adapter` alone exports
  non-empty hot items; strict clippy issues in router reject handling, WireGuard listen
  ports, test helper types, and async test locking were cleaned.
- **Test hygiene DONE locally**: the GeoIP provider placeholder test was replaced by a
  weak-owner registry integration test, hot-cache JSON assertions now catch empty-item
  regressions, and noisy success-path test `println!` output was removed or converted to
  assertions.
- **Verification PASS**: focused changed-test set, `cargo check -p sb-core --all-targets
  --all-features`, `cargo clippy -p sb-core --all-targets --all-features -- -D warnings`,
  `cargo test -p sb-core --all-targets --all-features`, `cargo fmt --check`,
  `git diff --check`, and `verify-consistency.sh`.
- **Scope note**: sb-core audit/test hygiene only. No REALITY closure, dual-kernel
  BHV/parity movement, release packaging completion, or workflow automation is claimed.

## Resume (2026-07-02) - grafana release hygiene

- **`grafana/` release hygiene DONE locally**: Grafana README/provisioning/docs now
  point at the current admin `ADMIN_LISTEN=:19090` + `/metricsz` scrape path, keep
  standalone `/metrics` on a separate developer exporter port, and no longer suggest
  mutable `latest` image tags.
- **Verification PASS**: Grafana metadata verifier checks dashboard datasource
  variables, unique dashboard UIDs, alert expressions, source-backed metric names, and
  stale scrape-token regressions.
- **Scope note**: Grafana monitoring asset hygiene only. No product behavior, release
  packaging completion, REALITY closure, dual-kernel BHV/parity movement, or workflow
  automation is claimed.

## Resume (2026-07-02) - fuzz release hygiene

- **`fuzz/` release hygiene DONE locally**: root core-dump ignore no longer hides
  `fuzz/targets/core/` or `fuzz/regression/core/`; core fuzz targets and regression
  anchor are tracked, fuzz metadata verification is wired into maintained entrypoints,
  unknown regression targets fail fast, and clean-all no longer removes tracked seeds.
- **Verification PASS**: metadata verifier, shell syntax, fmt, fuzz check/build,
  deterministic seed regeneration, invalid-target negative check, full seed replay,
  regression no-input path, consistency, and `git diff --check`.
- **Scope note**: fuzz harness/release hygiene only. No product behavior, release
  packaging completion, REALITY closure, dual-kernel BHV/parity movement, or workflow
  automation is claimed.

## Strategic State

Phase: MT-REAL-02 stage-2 closed; public fresh-cohort = pre-release observation
(non-gating). Parity **52/56 BHV (92.9%) unchanged** — REALITY has no S3 BHV-ID, not in the
S1/S6 denominator. DEV-REALITY-01 = ARCH-LIMIT: local profile parity CLOSED, official-JA4 + camouflage OPEN.

## Current Build And Gate

- check/build/clippy (all-features,all-targets): **PASS** locally on 2026-06-30.
  Clippy exits 0 with existing warning-level lint reports (lint relaxed 2026-06-03:
  warnings/dead_code deny→warn, safety kept deny).
- cargo check --workspace --all-features: **PASS**. strict check-boundaries.sh: **exit 0**.
- python3 unittest (reality_probe_tools / clienthello_family /
  dual_kernel_verification): **PASS**. trojan_integration: **20 PASS, 0 ignored**.

## T3 ClientHello Fingerprint Parity — T3-0…T3-2 DONE (2026-06-08)

- CLOSED (local): functional dataplane, normalized-profile parity, required field-set parity,
  coordinated GREASE structure, and local from-spec JA4 Go==Rust diagnostic.
- OPEN: official FoxIO-tool JA4 crosscheck, extension-order statistical parity,
  `HelloChrome_Auto` drift, tier-2 camouflage. NON-GOAL: L4 byte identity.
- A2.3 runtime status-JSON rehearsal DEFERRED. Detail: t32 governance; T3-1B `052d4392`.

## REALITY Acceptance (3-tier; golden_spec S4)

1. Local deterministic gate — `make verify-reality-local` (A1/A2 committed; A2.3 deferred).
2. External healthy-cohort observation — pre-release, NON-gating (tri-state; no single node
   is a closure identity; outage ≠ regression).
3. ClientHello fingerprint parity — tier-3: local profile parity CLOSED (see T3 section);
   official-JA4 + ext-order distribution + camouflage OPEN.

## Closed Tracks (compressed; detail in archive)

- **A4 projection** CLOSED through A4.4 (`a5b7a41f`+`b042a683`, 2026-06-06): route C canonical
  STRICT, projection TERMINAL; 34/34 projected, 0 promotable; deferred G1/G2/G3.
- **A2 REALITY-gate wiring** DONE (`71e51669`+`e44c67d3`, 2026-06-06): L18 REALITY_LOCAL gate
  after ORACLE; A2.3 runtime status-JSON DEFERRED.
- **MT-REAL-02 stage-2** closed (R45-R60): per-outbound rollup + planner --latest-* filters.
  History (fresh13 per-rep R73/R90/R91; fresh09 broken R85/R88): mt_real_02_baseline.md.

## Still-Valid Constraints

- Do not return to a static ClientHello template; do not hard-code precedence or
  position-to-mode behavior. (R12 seed-modes = stable sampler; R13 position coupling falsified.)
- Real node usability is not guaranteed; node outage is not sampler regression.
- The user pursues the highest goal, not maintenance-only posture; stage closure ≠ project closure.
- Any fresh-cohort live run must pass R81 subset-schema dry-run gate.
- closure scope is per-outbound + per-class; never extend A.1 to cohort-B group closure
  without the required same-class chain.
- A broken closure chain cannot be patched; restart needs a fresh consecutive sequence.
  A single-node recheck of a broken rep only opens a new chain at round 1.
- Rotated-replacement per-rep closure is not original-cohort closure.
- Public-node (cohort C / fresh09) closure = external-healthy-cohort observation, not a merge
  gate; no single node mandatory; merge-precheck = local gate only.
- Retired non-goal: original cohort-C closure (was bound to fresh09).

## Historical Detail

- R33-R60 + early ClientHello/Vision/REALITY: `mt_real_02_baseline.md`; L01-L25:
  `archive/l01_l25_summary.md`; closed MT-* tracks: `archive/mt_summary.md`;
  REALITY archive: `archive/reality_summary.md`; golden spec:
  `labs/interop-lab/docs/dual_kernel_golden_spec.md`.
