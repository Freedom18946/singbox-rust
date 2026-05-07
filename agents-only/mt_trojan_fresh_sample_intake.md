<!-- tier: A -->
# MT-TROJAN-FRESH-01 Trojan Fresh Sample Intake

> Separate quality line. This is not MT-REAL-02 REALITY/VLESS work and
> does not promote dual-kernel parity. BHV remains 52/56.

## Scope

The R72c input is valid JSON but belongs to the Trojan protocol family.
It cannot feed MT-REAL-02 R73 REALITY live probe. It may be useful as a
future bounded Rust-only Trojan realworld sanity sample, after a
non-live dry-run/probe runner exists.

## Safety Rules

- Do not commit `/tmp` configs or intake outputs.
- Do not write raw server, password, TLS server_name, or other node
  material to git, reports, or chat.
- Do not run live probes during intake.
- Do not treat Trojan sanity as dual-kernel parity completion.

## Safe Field Summary

Input summary, counted without printing values:

- `outbounds_len`: 90
- `type_counts`: `trojan=90`
- `has_password`: 90
- `has_tls`: 90
- `has_server`: 90
- `has_server_port`: 90
- `tls_enabled`: 90
- `tls_server_name`: 90
- `transport_type_counts`: `<absent>=90`

## Intake Tool

`scripts/tools/trojan_sample_intake.py` performs offline classification
and writes only redacted fingerprints:

- `trojan_ready`: required Trojan fields are present and TLS fields are
  interpretable.
- `duplicate`: repeated tag or repeated redacted fingerprint.
- `not_ready`: missing server, server_port, password, or invalid TLS
  shape.
- `unsupported`: non-Trojan outbound.

Fingerprint output contains only:

- `server_hash`
- `password_hash`
- `server_name_hash`
- `port`

## MT-TROJAN-FRESH-01 Result

Command:

```bash
python3 scripts/tools/trojan_sample_intake.py \
  --candidate-config /tmp/mt_real_02_fresh_config_wrapped.json \
  --output-json /tmp/trojan_fresh_intake.json \
  --redacted-md /tmp/trojan_fresh_intake.md
```

Redacted counts:

- `trojan_ready`: 88
- `duplicate`: 2
- `not_ready`: 0
- `unsupported`: 0
- `ready_for_trojan_sanity`: true

## MT-TROJAN-FRESH-01 Dry-Run Gate

No live probe was run. The repository currently has no bounded Trojan
realworld sanity dry-run/probe runner equivalent to the REALITY/VLESS
batch tooling, so the gate stops at **C: tooling gap**.

Next implementation step: add a Trojan-specific bounded runner that can
produce a non-live plan/dry-run summary before any live authorization.

## MT-TROJAN-FRESH-02 Dry-Run Runner

`scripts/tools/trojan_probe_plan.py` now builds a bounded, redacted,
non-network plan from the Trojan intake JSON and candidate config. It
selects only `trojan_ready` entries, verifies each selected row against
the candidate config by redacted fingerprint, and writes no raw server,
password, or TLS server_name values.

Command:

```bash
python3 scripts/tools/trojan_probe_plan.py \
  --intake-json /tmp/trojan_fresh_intake.json \
  --candidate-config /tmp/mt_real_02_fresh_config_wrapped.json \
  --target example.com:80 \
  --limit 5 \
  --runs 1 \
  --timeout 8 \
  --output-json /tmp/trojan_probe_plan.json \
  --redacted-md /tmp/trojan_probe_plan.md
```

Redacted dry-run summary:

- `selected_count`: 5
- `total_ready`: 88
- `duplicate_count`: 2
- `planned_runs`: 5
- `dry_run_only`: true
- `ready_for_live_authorization`: true

## MT-TROJAN-FRESH-03 Live Authorization Decision

Date: 2026-05-07.

No explicit Trojan live authorization was provided in this round. Per
gate rules, no live pre-gate and no live probe were run. The existing
redacted dry-run plan remains ready for a future authorization decision:

- `selected_count`: 5
- `runs`: 1
- `target`: `example.com:80`
- `planned_runs`: 5
- `ready_for_live_authorization`: true

Classification: **A - ready but waiting for live authorization**.

## MT-TROJAN-FRESH-04 Bounded Live Sanity

Date: 2026-05-07.

Authorization was explicitly granted only for the existing bounded
Trojan plan. The pre-gate was rerun without expanding scope:

- `trojan_ready`: 88
- `duplicate`: 2
- `not_ready`: 0
- `unsupported`: 0
- `selected_count`: 5
- `runs`: 1
- `target`: `example.com:80`
- `timeout`: 8
- `planned_runs`: 5

Live evidence is redacted and stored outside git at
`/tmp/trojan_live_sanity.json` and `/tmp/trojan_live_sanity.md`.
Summary:

- `executed_runs`: 5
- `ok_count`: 0
- `failed_count`: 5
- `env_limited_count`: 0
- `tool_error_count`: 5
- `status_counts`: `tool_error=5`
- `class_counts`: `other=5`
- `probe_invocations`: 5
- `node_contact_confirmed`: false

Classification: **C - tooling gap discovered**. The bounded live runner
was authorized and invoked, but all runs failed before producing a
structured bridge_probe result. No Trojan node usability or code
conclusion is drawn from this round.

## MT-TROJAN-FRESH-05 No-Live Diagnostic Enrichment

Date: 2026-05-07.

No live probe was authorized or run in this round. The FRESH-04 evidence
was reviewed using only redacted data:

- `status_counts`: `tool_error=5`
- `class_counts`: `other=5`
- `node_contact_confirmed`: false

Root cause / narrow blocker: FRESH-04 preserved the redacted aggregate
result but discarded subprocess returncode/stdout/stderr diagnostics.
Because of that, the exact `probe-outbound` failure point cannot be
recovered from the existing evidence. The current blocker is runner
diagnostic under-instrumentation, not a Trojan node quality conclusion
and not a Rust dataplane conclusion.

`scripts/tools/trojan_probe_live.py` now enriches future evidence with:

- `returncode`
- `tool_diagnostic.stdout_kind`: `empty`, `non_json`,
  `json_missing_bridge_probe`, or `json_bridge_probe`
- `tool_diagnostic.stderr_present`
- `tool_diagnostic.stdout_sha256_12`
- `tool_diagnostic.stderr_sha256_12`
- `tool_diagnostic.scrubbed_excerpt`

Tool-layer classes now distinguish stdout non-JSON, JSON missing
`bridge_probe`, CLI usage errors, cargo/build errors, missing tools,
timeouts, and unknown tool failures. Excerpts are bounded and scrubbed
against the actual candidate config's server/password/TLS server_name
values before evidence is written.

Live remains prohibited until a future task explicitly authorizes a new
bounded run.

## MT-TROJAN-FRESH-06 Enriched Bounded Live Reprobe

Date: 2026-05-07.

Authorization was explicitly granted only for reusing the existing
bounded Trojan plan. The pre-gate was rerun without expanding scope:

- `trojan_ready`: 88
- `duplicate`: 2
- `not_ready`: 0
- `unsupported`: 0
- `selected_count`: 5
- `runs`: 1
- `target`: `example.com:80`
- `timeout`: 8
- `planned_runs`: 5
- `ready_for_live_authorization`: true

Redacted reprobe evidence is stored outside git at
`/tmp/trojan_live_sanity_r06.json` and
`/tmp/trojan_live_sanity_r06.md`.

Summary:

- `classification`: C
- `executed_runs`: 5
- `ok_count`: 0
- `failed_count`: 5
- `tool_error_count`: 5
- `env_limited_count`: 0
- `status_counts`: `tool_error=5`
- `class_counts`: `tool_unknown=5`
- `probe_invocations`: 5
- `node_contact_confirmed`: false

Enriched diagnostics were identical across the 5 bounded invocations:

- `returncode`: 1
- `stdout_kind`: `empty`
- `stderr_present`: true
- `stdout_sha256_12`: none
- `stderr_sha256_12`: `6b7e83d248cf`

Root cause / narrow blocker: `probe-outbound` fails during local config
loading before it can produce `bridge_probe`. The candidate config still
contains a GUI-only unknown field at `/outbounds/0/__id_in_gui`, and the
Rust config loader rejects that field. No node contact was structurally
confirmed, so this remains a tooling/config-normalization gap rather
than a Trojan node quality or Rust dataplane conclusion.

The live runner now classifies this pattern as
`config_validation_unknown_field` for future diagnostics. Live remains
prohibited until a future task explicitly authorizes a bounded rerun
after the config-normalization gap is addressed.

## Verification

- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py scripts/tools/test_reality_clienthello_family.py scripts/tools/test_dual_kernel_verification.py`
  -> 99 PASS.
- `cargo check --workspace` -> PASS.

## Classification

**C - Tooling gap narrowed to config normalization for `probe-outbound`.**
Trojan planning and intake remain separate Rust-only quality work and
do not affect BHV 52/56 or dual-kernel parity status.

## MT-TROJAN-FRESH-07 Config Normalization + No-Dial Preflight

Date: 2026-05-07.

No live probe was authorized or run. This round addressed only the
FRESH-06 local config-validation blocker before any node contact.

Normalization wrote a probe-only config outside git at
`/tmp/mt_trojan_fresh_config_normalized.json` and redacted summaries at
`/tmp/mt_trojan_fresh_config_normalized_summary.json` and
`/tmp/mt_trojan_fresh_config_normalized_summary.md`.

Normalized config summary:

- `outbounds_count`: 90
- `ready_for_no_dial_preflight`: true
- removed GUI/private fields: `__id_in_gui=90`

The Trojan intake and plan dry-run were rerun against the normalized
shape without changing the selected sample:

- `trojan_ready`: 88
- `duplicate`: 2
- `not_ready`: 0
- `unsupported`: 0
- `selected_count`: 5
- `total_ready`: 88
- `planned_runs`: 5
- `target`: `example.com:80`
- `timeout`: 8
- `ready_for_live_authorization`: true

`probe-outbound` now has a validate-only preflight mode that emits
`no_network=true` and exits after config load, IR conversion, selected
outbound lookup, bridge assembly, and bridge member lookup. It exits
before direct probes, bridge probes, `connector.connect`, or
`connect_io`.

No-dial preflight evidence is stored outside git at
`/tmp/trojan_no_dial_preflight_r07.json` and
`/tmp/trojan_no_dial_preflight_r07.md`.

No-dial preflight summary:

- `classification`: A
- `selected_count`: 5
- `preflight_invocations`: 5
- `passed_count`: 5
- `failed_count`: 0
- `runs`: 1
- `planned_runs`: 5
- `no_network`: true
- `node_contact_confirmed`: false
- `ready_for_future_live_authorization`: true

Classification: **A - normalized config passes no-dial preflight and is
ready for future bounded Trojan live authorization**. This remains a
separate Rust-only quality line and does not affect BHV 52/56 or
dual-kernel parity status.
