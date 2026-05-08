# R81 - Subset-schema pre-gate hardening (no-live, tooling)

Authorization: none required (no live, no node contact, no sampler/dataplane changes). Closes the R80 pre-gate gap.

## Pre-gate

- HEAD at gate: b9729f52; main synced with origin/main: true
- Scope: tooling/no-live
- Live executed: no
- Node contact executed: no
- BHV: 52/56 unchanged

## What R80 exposed

R80 returned classification C (tooling/config blocker). All 3 fresh04 matrix runs returned `matrix_error` because the rust app config validator rejected `__id_in_gui` carried over from a neutralized REALITY subset. The pre-gate dry-run did not catch it because dry-run does not load the config in the rust app process.

R76 plan-C had already predicted this operational path: dry-run is structurally weaker than the live matrix because the rust binary never gets the subset at dry-run time. R80 confirmed it operationally and produced the canonical failure shape (`unknown field at /outbounds/0/__id_in_gui`).

## What R81 changes

- New module: `scripts/tools/reality_vless_subset_schema_gate.py`
- Wired into dry-run path of: `scripts/tools/reality_vless_probe_batch.py`
- Live path: untouched

### Rule contract

- Outbound-level fields with prefix `__` are rejected (catches GUI-only fields like `__id_in_gui`).
- Outbound-level fields not in the curated REALITY/VLESS allow-list are rejected (separate branch from the prefix rule, with a distinct reason string so future regressions cannot collapse the two).
- Nested fields with prefix `__` are rejected at any depth (covers GUI residue inside `tls`, `transport`, etc.).
- Nested whitelisting is **not** enforced; the rust loader's nested schema is large and protocol-shape-specific, matching it exactly is out of R81 scope.
- Field VALUES are never read or surfaced. Violations carry only `{path, field, reason}` so sensitive material (uuid, public_key, short_id, server_name, server, tag, password) stays in the local input file.

### Allow-list source

`crates/sb-config/src/outbound/raw.rs::RawVlessConfig` (the `deny_unknown_fields` boundary type) plus the compat aliases handled by `crates/sb-config/src/compat.rs::compat_v1_to_v2` (`tag` <-> `name`, `server_port` <-> `port`).

The allow-list is REALITY/VLESS-scoped on purpose; it is **not** a union over every protocol's outbound fields. Tightening here catches GUI-side residue the rust loader would also reject.

### Behavior

| Mode | Gate result | plan.json / summary.json | exit code |
| --- | --- | --- | ---: |
| `--dry-run` | gate fails | `subset_schema_gate_passed=false` + violations list | 2 |
| `--dry-run` | gate passes | `subset_schema_gate_passed=true` | 0 |
| live (no `--dry-run`) | n/a | gate keys absent (shape unchanged from pre-R81) | 0 (same as before) |

The non-zero exit on dry-run gate failure ensures cohort/orchestration scripts treat the dry-run as not-passed and refuse to escalate to live.

## Compat audit

| Tool | Result |
| --- | --- |
| `reality_vless_confirmation_cohorts.py` | no break — operates on round_summary shape; does not consume probe_batch dry-run output |
| `reality_vless_probe_plan.py` | no break — uses dict.get and pre-existing fields only |
| `reality_vless_probe_evidence.py` | no break — uses dict.get on plan/summary; new fields are forward-compatible additions |

No dry-run shape consumer is broken. Adding `subset_schema_gate_passed` and `subset_schema_gate` to dry-run output is a net additive change.

## Tests

- Unittest modules: `test_reality_probe_tools`, `test_reality_clienthello_family`, `test_dual_kernel_verification`
- Baseline before R81: **176 PASS**
- R81 added: **14 tests** (11 active + 3 committed-evidence contract)
- Measured after R81: **190 PASS**

### Branch coverage in R81 unittests

- double-underscore prefix at outbound level (distinct reason)
- non-underscore unknown field at outbound level (whitelist branch, distinct reason)
- nested double-underscore at any depth
- cleansed subset passes
- redaction: violations carry only path/field/reason, no raw values
- dry-run integration: gate failure -> exit 2, plan/summary/stdout carry `subset_schema_gate_passed=false`
- dry-run integration: gate pass -> exit 0, plan/summary carry `subset_schema_gate_passed=true`
- live path unchanged: no gate keys on plan/summary
- allow-list scope: required reality/vless fields in, foreign-protocol fields out
- non-object subset root
- non-vless outbound entry
- committed-evidence contract: scope and no-live flags
- committed-evidence contract: classification and redaction
- committed-evidence contract: tooling change and compat audit

## Redaction

- No raw uuid / public_key / short_id / password / tag / server / server_name in committed files.
- All R81 unittest fixtures use synthetic redacted values (e.g. `"redacted-uuid"`, `"redacted.example.invalid"`).
- Secret scan run against all modified and new files: 0 findings.

## Classification

**A — actionable; tooling hardening; no live; no node contact.**

R81 closes a structural pre-gate gap exposed by R80. The fix is a no-live, no-node-contact, no-sampler/dataplane-touching tooling addition that surfaces the schema-mismatch failure class at dry-run time, before any live authorization is granted. Future fresh-cohort live runs (fresh04 retest, cohort C round-2, R73 unselected recovery nodes) benefit from this gate. BHV 52/56 unchanged; not a parity completion; not a sampler/dataplane regression.

## Follow-up

- fresh04 retest is still pending. R81 does not authorize any live run.
- Recommended: **R82 fresh04 same-failure recheck with cleansed subset** (same scope as R80: fresh04 only, REALITY/VLESS only, x3 runs, no auto-extension). Requires explicit user re-authorization per the existing cohort-authorization discipline.

## Range confirmation

- live runs in R81: 0
- node contacts in R81: 0
- sampler / dataplane changes in R81: 0
- `go_fork_source/*` / `.github/workflows/*` changes in R81: 0
- BHV 52/56 unchanged at round time
- Not dual-kernel parity completion; Rust-only quality / tooling
