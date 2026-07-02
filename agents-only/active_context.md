<!-- tier: S -->
# Active Context

> Purpose: high-frequency project navigation. S-tier: read every
> session.
> Discipline: keep only current-stage facts. This file must stay
> under 300 lines.
> **This file is the single source of truth for volatile state**
> (phase, parity-BHV, build/gate). Other docs point here, not copy.

---

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

## Resume (2026-07-01) - examples release hygiene

- **`examples/` release hygiene DONE locally**: runnable samples stay on current
  `schema_version: 2`/`when`/`to` shapes, code examples build from their own manifest,
  subscription node-list schema now matches the array fixtures, and legacy `misc/`
  migration helpers have valid route actions.
- **Verification PASS**: JSON/YAML parse, strict `app check` for `quick-start/` and
  `configs/`, legacy `misc/` migration/current checks, negative config fixture failure,
  route explain smoke, code-example build, subscription schema fixture test, fmt, and
  `git diff --check`.
- **Scope note**: examples/schema-fixture hygiene only. No product behavior, release
  packaging completion, REALITY closure, dual-kernel BHV/parity movement, or workflow
  automation is claimed.

## Resume (2026-07-01) - docs release hygiene

- **`docs/` release hygiene DONE locally**: live docs were aligned with current
  source-first examples, disabled workflow policy, `app` binary invocation, maintained
  `deployments/` assets, and admin `/metricsz` operations path. Historical docs keep
  provenance banners; live docs no longer advertise workflow-generated release artifacts.
- **Verification PASS**: strict `app check`, `route --explain --with-trace`, and
  `run --check` for `examples/quick-start/01-minimal.json`; docs local-link scan;
  active-doc stale-command scan; `git diff --check`.
- **Scope note**: documentation hygiene only. No product behavior, release packaging
  completion, REALITY closure, dual-kernel BHV/parity movement, or workflow automation
  is claimed.

## Resume (2026-07-01) - deployments release hygiene

- **`deployments/` release hygiene DONE locally**: compose, Docker, Helm, Kubernetes, and
  sample config surfaces were cleaned for reproducible defaults and current config
  validation. Example proxy secrets now use env-backed credentials with `.invalid`
  sample hosts; compose/Kubernetes/Helm image defaults use explicit app-version tags;
  Docker build context now includes all workspace members needed by the root manifest;
  Helm serviceAccount values are wired into rendered pods.
- **Verification PASS**: strict `app check` for deployment config samples, JSON parse,
  non-template YAML parse, both Docker Compose config expansions, residual placeholder/
  `latest` scans, serviceAccount wiring scan, and `git diff --check`.
- **Unavailable local gates**: Helm rendering was not run because `helm` is not installed;
  Docker build/manifest probes were blocked by the local Docker/registry environment;
  Kubernetes client dry-run was blocked by the absent local API server.
- **Scope note**: deployment-template hygiene only. No release packaging completion,
  REALITY closure, dual-kernel BHV/parity movement, or workflow automation is claimed.

## Resume (2026-06-30) - app release hygiene

- **`app/` release hygiene DONE locally**: removed dead/undiscoverable app source, empty or
  permanently disabled placeholder tests, simulated performance/validation tests, and ignored
  stale `app/target/rc` artifacts.
- **Analyze patch API fixed**: app registry now delegates supported patch kinds to real
  `sb_core::router::analyze_fix` builders; `supported_patch_kinds()` accepts current
  `patch_kinds` payloads. The implicit `merge` bin is now explicit in `app/Cargo.toml`.
- **Verification PASS**: `cargo test -p app --all-features --test registry_demo`;
  `cargo test -p app --all-features supported_patch_kinds_parse_current_core_payload`;
  `cargo check -p app --all-targets --all-features`; focused performance/protocol/
  Shadowsocks/HTTP-chain tests; `cargo fmt --check`; `git diff --check`.
- **Scope note**: app hygiene only. No REALITY closure, dual-kernel BHV/parity movement,
  workflow automation, or release packaging completion is claimed.

## Previous Resume (2026-06-30) - root files release acceptance

- **Root file acceptance DONE locally**: the requested root release/navigation/config
  file set received a release-level hygiene pass. The stale workspace fuzz exclude
  now points at root `fuzz/`, README no longer treats `agents-only/log.md` as the
  volatile-state source, and `deny.toml` records the remaining no-fixed-release
  `rsa` advisory exception for the optional Arti/Tor graph.
- **Dependency/API hygiene DONE locally**: hickory moved to 0.26 across `app`,
  `sb-core`, and `interop-lab`; russh moved to 0.60.3 for SSH adapters; app JWT
  dropped direct `rsa`/`pkcs1` and now builds RS256 JWK decoding keys from RSA
  components. Root and fuzz lockfiles were refreshed by local gates.
- **Verification PASS**: historical record compressed in `agents-only/archive/release_cleanup_2026_06_summary.md`.
  Format, focused JWT test, app/adapters all-features checks, workspace check,
  workspace all-features/all-targets clippy, cargo-deny advisories/license/bans/
  sources, fuzz-check, metadata workspace-membership check, Makefile dry-run,
  docs-link check, and boundaries passed locally. Clippy and deny still emit
  existing warning-level diagnostics but exit 0.
- **Spike note**: no spike artifact was deleted in this round. Tracked A41/A42
  spike materials remain historical projection/mapping evidence, not an expiry
  cleanup target.
- **Scope note**: root/config/dependency hygiene only. No product behavior claim,
  REALITY closure, dual-kernel BHV/parity movement, workflow automation, or release
  packaging completion is claimed.

## Previous Resume (2026-06-30) - Claude memory cleanup policy refresh

- **`.claude` record reverted**: pushed commit `0a7c3abc` (tracked `agents-only` documentation about
  `.claude/`) was reverted by `5bca4f5f`; local `.claude/` remains present, ignored, and untracked.
- **Cleanup discipline updated**: root `CLAUDE.md` and Claude project memory now record the user rule:
  cleanup tasks must ask delete vs update/keep before acting; `.claude/` is Claude Code local state
  and must not be tracked, staged, committed, pushed, or documented in tracked artifacts unless
  explicitly requested.
- **Scope note**: memory/policy correction only. No product behavior, workflow automation, release
  packaging, REALITY closure, or dual-kernel BHV/parity movement is claimed.

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
