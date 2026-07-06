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

## MT-TROJAN-FRESH-08 Normalized Bounded Live Sanity

Date: 2026-05-07.

Authorization was explicitly limited to the FRESH-07 normalized config
and the existing bounded 5x1 Trojan plan. No REALITY live probe,
sampler/dataplane change, sample expansion, or parity promotion was
performed.

The FRESH-07 pre-gate was rerun before live:

- normalized config: `/tmp/mt_trojan_fresh_config_normalized.json`
- removed GUI/private fields: `__id_in_gui=90`
- `ready_for_no_dial_preflight`: true
- validate-only `selected_count`: 5
- validate-only `passed_count`: 5
- validate-only `failed_count`: 0
- validate-only `no_network`: true
- validate-only `node_contact_confirmed`: false

Redacted live evidence is stored outside git at
`/tmp/trojan_live_sanity_r08.json` and
`/tmp/trojan_live_sanity_r08.md`.

Live summary:

- `classification`: A
- `selected_count`: 5
- `runs`: 1
- `target`: `example.com:80`
- `timeout`: 8
- `planned_runs`: 5
- `executed_runs`: 5
- `ok_count`: 0
- `failed_count`: 5
- `env_limited_count`: 0
- `tool_error_count`: 0
- `status_counts`: `probe_error=5`
- `class_counts`: `other=5`
- `node_contact_confirmed`: true

Conclusion: the FRESH-06 local config-load blocker is cleared by
normalization, and the runner now reaches structured `bridge_probe`.
The bounded signal is five structured connect-stage failures through
`connect_io`, all currently classified as `other`. This is useful live
runner evidence, not a Trojan node-quality pass and not a Rust dataplane
or dual-kernel parity conclusion. Further live work still requires a new
explicit authorization.

## MT-TROJAN-FRESH-09 Structured Bridge-Probe Class Refinement, No-Live

Date: 2026-05-07.

No live probe was authorized or run. This round only enriched the
runner so a future authorized live round can produce an explainable
class instead of the FRESH-08 `other=5` aggregate.

FRESH-08 evidence review (`/tmp/trojan_live_sanity_r08.json`):

- 5/5 results were structured `bridge_probe` at `stage=connect`,
  `stream_mode=connect_io`, `connect_time_ms=0`, `class=other`.
- The runner preserved a 180-character scrubbed stderr excerpt that
  fingerprints the wrapper's `connect()` rejection
  (`uses encrypted stream`), but the trailing `connect_io` failure that
  determined `class=other` was truncated and the structured
  `bridge_probe.error` / `bridge_probe.raw_connect_error` JSON fields
  were never copied into evidence. Status: structured bridge diagnostic
  was under-instrumented — no node-quality conclusion, no dataplane
  conclusion. The expected wrapper behavior (`AdapterIoBridge::connect`
  refusing the plaintext probe and the runner falling back to
  `connect_io`) is recoverable, but the actual `connect_io` failure
  reason is not.

`scripts/tools/trojan_probe_live.py` now records a redacted
`bridge_diagnostic` for every structured failure:

- `error_kind`: refined class from the connect / connect_io error chain.
- `error_sha256_12`: SHA-256 prefix of `bridge_probe.error`.
- `raw_connect_error_sha256_12`: SHA-256 prefix of
  `bridge_probe.raw_connect_error`.
- `scrubbed_excerpt`: bounded combined excerpt with all candidate-config
  server, password, and TLS server_name values replaced by
  `<redacted:hash>`.

Refined classes available to the runner now (priority highest to lowest
within `BRIDGE_CLASS_PATTERNS`):

- `dns_error`
- `network_unreachable`
- `handshake_eof`
- `tls_error`
- `auth_failed`
- `connection_refused`
- `connection_reset`
- `timeout`
- `unexpected_response`
- `unsupported_protocol` (lowest — only fires when the chain leaks no
  stronger signal, since `uses encrypted stream` is the expected
  first-attempt rejection on encrypted-stream protocols)
- `unknown_probe_failure` (fallback — never `other`)

Already-specific classes from `probe-outbound`
(`timeout`, `connection_refused`, `connection_reset`, `permission_denied`,
`post_dial_eof`, `broken_pipe`, `socks_connect`, `http2_framing`,
`reality_dial_eof`, `handshake_eof`) are kept as-is.

Verification:

- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py
  scripts/tools/test_reality_clienthello_family.py
  scripts/tools/test_dual_kernel_verification.py` -> 123 PASS.
- `cargo check --workspace` -> PASS.
- `cargo build -p app --features router,adapters --bin probe-outbound`
  -> PASS.
- `cargo test -p app --features router,adapters --bin probe-outbound`
  -> 6 PASS.
- `git diff --check` -> clean.
- Secret scan against the 270 raw `/tmp` candidate-config positions
  (5 unique values across `server`, `password`, TLS `server_name` for
  90 normalized outbounds) found no leak in the diff, the modified
  scripts, the agent docs, or any redacted `/tmp/trojan_*` evidence.

Live remains prohibited. A future explicit authorization is still
required before any new bounded run; the new diagnostic gives that run a
chance to produce an actionable refined class instead of `other`.

Classification: **A — runner now emits a refined `bridge_diagnostic`
and never surfaces `other` from a structured `bridge_probe` failure**.
This is a Rust-only quality line and does not affect BHV 52/56 or
dual-kernel parity.

## MT-TROJAN-FRESH-10 Refined Bounded Trojan Live Reprobe

Date: 2026-05-07.

Authorization was explicitly limited to one bounded reprobe of the
existing FRESH-07 normalized config and the FRESH-09 refined runner.
No REALITY live probe, sampler/dataplane change, sample expansion, or
parity promotion was performed.

Pre-gate (validate-only on each of the 5 selected tags) using
`./target/debug/probe-outbound --validate-config-only --json`:

- `preflight_invocations`: 5
- `passed_count`: 5
- `failed_count`: 0
- `no_network`: true (every invocation)
- `outbound_type`: `trojan` (every invocation)
- `selected_found` and `bridge_member_found`: true (every invocation)
- `node_contact_confirmed`: false

Bounded live reprobe:
- plan: `/tmp/trojan_probe_plan.json` (re-verified identical to a
  fresh rebuild from the normalized intake — same 5 server/password/
  port fingerprints, no sample re-selection)
- candidate config: `/tmp/mt_trojan_fresh_config_normalized.json`
- target: `example.com:80`
- timeout: 8
- `selected_count`: 5; `runs`: 1; `planned_runs`: 5

Redacted live evidence is stored outside git at
`/tmp/trojan_live_sanity_r10.json` and `/tmp/trojan_live_sanity_r10.md`.

Live summary:

- `classification`: A
- `executed_runs`: 5
- `ok_count`: 0
- `failed_count`: 5
- `env_limited_count`: 0
- `tool_error_count`: 0
- `status_counts`: `probe_error=5`
- `class_counts`: `unsupported_protocol=5` (no literal `other`)
- `node_contact_confirmed`: true

Refined bridge diagnostic (identical fingerprint across all 5 runs;
deterministic):

- `error_kind`: `unsupported_protocol`
- `error_sha256_12`: `1198e52870f3`
- `raw_connect_error_sha256_12`: `65828a0ea9d6`
- `scrubbed_excerpt` (single representative; all 5 share the same
  fingerprint): `dial outbound via connect_io after connect error:
  trojan adapter uses encrypted stream for example.com:80; use
  connect_io() instead: trojan dial failed: Other error: Invalid
  server...`

Narrowest live signal / blocker: the `connect_io` chain reveals an
internal Trojan adapter rejection — the full unscrubbed connect_io
error is `trojan dial failed: Other error: Invalid server address:
invalid socket address syntax`. Source: `crates/sb-adapters/src/
outbound/trojan.rs:363` calls `config.server.parse::<SocketAddr>()`,
but `config.server` is built at `crates/sb-adapters/src/register.rs:
1007` as `format!("{}:{}", server, port)` — a `hostname:port` string,
which `SocketAddr::parse` rejects because it requires `IP:port`. This
fails synchronously, before any network IO, for every Trojan outbound
whose `server` is a hostname rather than an IP literal. It applies
equally to all 5 selected entries (and structurally to all 88
trojan_ready candidates in the sample).

Why the class label is `unsupported_protocol`: the FRESH-09 refinement
table has no pattern for `Invalid server address`, so the classifier
falls through to the lowest-priority wrapper-rejection signal (`uses
encrypted stream` from `raw_connect_error`). The label is technically
coarse — the actionable detail is in `bridge_diagnostic.scrubbed_excerpt`
rather than the class name. This is a tooling-refinement opportunity
(adding an `invalid_server_address` / `dataplane_config_error` pattern),
not a regression: FRESH-08 returned `class=other=5` with no recoverable
detail; FRESH-10 returns the same connect_io text fully redactable and
operator-readable.

Blockers (recorded only; per task scope, not fixed this round):

1. Rust dataplane: `TrojanConnector::dial`
   (`crates/sb-adapters/src/outbound/trojan.rs:363`) cannot accept
   hostname-format `config.server`. Either resolve hostname before
   `SocketAddr::parse`, or store host and port separately in
   `TrojanConfig` so the adapter does not need to re-split a
   self-built `host:port` string.
2. Tooling (FRESH-09 refinement table): add patterns for
   `invalid server address`, `Other error: Invalid` so that future
   runs surface a class name closer to the underlying signal instead
   of falling back to `unsupported_protocol`.

Next live authorization: not needed against the same plan / dataplane
combination — the failure is deterministic and another run would
reproduce identical fingerprints. A future bounded live run is only
useful after either blocker (1) or a sample with IP-literal `server`
values is in place. Live remains otherwise prohibited.

Verification:

- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py
  scripts/tools/test_reality_clienthello_family.py
  scripts/tools/test_dual_kernel_verification.py` -> 123 PASS.
- `cargo check --workspace` -> PASS.
- `cargo build -p app --features router,adapters --bin probe-outbound`
  -> PASS.
- `cargo test -p app --features router,adapters --bin probe-outbound`
  -> 6 PASS.
- `git diff --check` -> clean.
- Secret scan against the 270 raw `/tmp` candidate-config positions
  (5 unique values across `server`, `password`, TLS `server_name` for
  90 normalized outbounds) — no leak in the diff, modified docs, or
  any `/tmp/trojan_*` redacted evidence.

Classification: **A — refined actionable live signal, structured
bridge_probe, no `tool_error`, no literal `other`, dataplane blocker
recorded for a future round**. Rust-only quality line, BHV 52/56
unchanged.

## MT-TROJAN-FRESH-11 Trojan Hostname Server Dataplane Fix, No-Live

Date: 2026-05-07.

No live probe was authorized or run. This round fixes the FRESH-10
dataplane blocker and tightens the FRESH-09 classifier so the same
signal would be labeled accurately on a future authorized live run.

Root cause fixed: `crates/sb-adapters/src/outbound/trojan.rs` formerly
called `config.server.parse::<SocketAddr>()` in both the TCP `dial`
path and the `udp_relay_dial` path. `SocketAddr::parse` requires an
IP literal, so any hostname `server` (which `register.rs:1007`
constructs as `format!("{}:{}", server, port)`) failed synchronously
with `Invalid server address: invalid socket address syntax` before
any network IO. This applied to every hostname-format Trojan outbound,
including all 88 trojan_ready entries in the FRESH-07 sample.

Changed dataplane behavior:

- New `parse_server_endpoint(server)` returns `(host: String, port:
  u16)` from `domain:port`, `IPv4:port`, or `[IPv6]:port`. It rejects
  empty hosts, missing / empty / non-numeric / zero ports, unclosed
  IPv6 brackets, and bare (unbracketed) IPv6 strings. It does NOT
  require the host to be an IP literal.
- TCP `dial()` now resolves DNS at the transport layer:
  - Detour path: `connect_tcp_stream(&server_host, server_port, ...)`
    (already supports hostnames via `TcpStream::connect((host, port))`).
  - sb-transport dialer path: `dialer.connect(&server_host,
    server_port)` (the Dialer trait already takes `&str` host).
  - Direct fallback: `tokio::net::TcpStream::connect((server_host
    .as_str(), server_port))` (DNS via the Tokio resolver).
- A hostname `server` no longer surfaces `Invalid server address` at
  the local parse stage. Any failure is now a downstream DNS / TCP /
  TLS / Trojan-handshake error.

UDP relay path decision:

- `udp_relay_dial` still needs a concrete `SocketAddr` to drive
  `UdpSocket::connect` and to encode the UDP ASSOCIATE record. The
  fix resolves hostnames via `tokio::net::lookup_host((host, port))`
  and picks the **first** returned `SocketAddr`. On resolution failure
  or empty result, returns `AdapterError::Network` with the explicit
  text `Trojan UDP relay DNS resolution failed for ...` /
  `Trojan UDP relay DNS resolution returned no addresses for ...` so
  the failure is observable, not silent.
- Pre-existing limitations explicitly **NOT** fixed in this round:
  the UDP path does not round-robin across multiple resolved
  addresses, and the UDP ASSOCIATE record is hardcoded to ATYP=0x01
  (IPv4) — an IPv6-only resolved server would still misencode the
  record. These are recorded here as future blockers; they are not
  introduced by FRESH-11 and were already present pre-fix.

Classifier update (`scripts/tools/trojan_probe_live.py`):

- New refined class `invalid_server_address` placed at the **top** of
  `BRIDGE_CLASS_PATTERNS` so any chain that carries either
  `Invalid server address` or `invalid socket address syntax` wins
  over the wrapper-rejection prefix `uses encrypted stream`. Old
  `/tmp` evidence (FRESH-08, FRESH-10 raw streams) re-classified
  through this table now produces `invalid_server_address=5` instead
  of `unsupported_protocol=5`.

Remaining blocker:

- UDP IPv6 / round-robin: see "Pre-existing limitations" above. Not
  blocking FRESH-10's TCP-only sample.
- Live re-validation against FRESH-07 sample is gated on a future
  explicit authorization. The deterministic `Invalid server address`
  failure surface is gone; downstream DNS / TLS errors are expected
  but not reproducible without live network IO.

No-live / no-node-contact confirmation:

- Live remains prohibited and was not exercised. Only no-live
  verification ran:
  - 13 new Trojan unit tests (`parse_server_endpoint_*` plus the
    pre-existing connector creation test) under
    `cargo test -p sb-adapters --features adapter-trojan --lib
    outbound::trojan::tests`.
  - 15 Trojan integration tests under
    `cargo test -p sb-adapters --features adapter-trojan --test
    trojan_integration`, including the new
    `test_trojan_hostname_server_does_not_fail_at_local_parse`
    regression. The regression dial uses a `.invalid` hostname per
    RFC 6761, bounded by a 500ms connect timeout, and asserts the
    error message contains neither `invalid socket address syntax`
    nor `Invalid server address`.
  - `probe-outbound --validate-config-only --json` against
    `/tmp/mt_trojan_fresh_config_normalized.json` reports
    `no_network=true`, `selected_found=true`, `bridge_member_found=
    true`.
- No probe-outbound `--target` dial. No `trojan_probe_live.py` live
  invocation. No node contact.

Verification:

- `python3 -B -m unittest test_reality_probe_tools
  test_reality_clienthello_family test_dual_kernel_verification` ->
  126 PASS (was 123; +3 for new `invalid_server_address` patterns).
- `cargo test -p sb-adapters --features adapter-trojan --test
  trojan_integration` -> 15 PASS, 2 ignored (pre-existing).
- `cargo check --workspace` -> PASS.
- `cargo build -p app --features router,adapters --bin probe-outbound`
  -> PASS.
- `cargo test -p app --features router,adapters --bin probe-outbound`
  -> 6 PASS.
- `git diff --check` -> clean.
- Secret scan against the 270 raw `/tmp` candidate-config positions
  (5 unique values across `server`, `password`, TLS `server_name` for
  90 normalized outbounds) found no leak in the diff, the modified
  Rust sources, the Python tooling, the agent docs, or any redacted
  `/tmp/trojan_*` evidence.

Classification: **A — Trojan hostname server dataplane blocker fixed
with full no-live verification; classifier no longer mislabels the
historic signal as `unsupported_protocol`**. Rust-only quality line,
BHV 52/56 unchanged.

## MT-TROJAN-FRESH-12 Post-Fix Bounded Trojan Live Reprobe

Date: 2026-05-07.

Authorization was explicitly limited to one bounded reprobe of the
existing FRESH-07 normalized config and the existing bounded plan,
under the FRESH-11 fixed Rust dataplane. No REALITY live, no
sampler/dataplane modification, no sample expansion, no live
authorization expansion.

Pre-gate (`./target/debug/probe-outbound --validate-config-only
--json` per selected tag):

- normalizer rerun: `outbounds_count=90`, `__id_in_gui=90` removed,
  `ready_for_no_dial_preflight=true`
- intake rerun: `trojan_ready=88`, `duplicate=2`, `not_ready=0`,
  `unsupported=0`
- plan re-verified identical to existing
  `/tmp/trojan_probe_plan.json` — same 5 server/password/port
  fingerprints, no sample re-selection
- preflight: `preflight_invocations=5`, `passed_count=5`,
  `failed_count=0`, `no_network=true`, `outbound_type=trojan` x5,
  `selected_found=true` x5, `bridge_member_found=true` x5,
  `node_contact_confirmed=false`

Bounded live reprobe:

- plan: `/tmp/trojan_probe_plan.json`
- candidate config: `/tmp/mt_trojan_fresh_config_normalized.json`
- target: `example.com:80`, timeout: 8, runs: 1, planned_runs: 5
- redacted evidence: `/tmp/trojan_live_sanity_r12.json`,
  `/tmp/trojan_live_sanity_r12.md`

Live summary:

- `classification`: A
- `executed_runs`: 5
- `ok_count`: 0
- `failed_count`: 5
- `env_limited_count`: 0
- `tool_error_count`: 0
- `status_counts`: `probe_error=5`
- `class_counts`: `tls_error=5` (no `invalid_server_address`, no
  `unsupported_protocol`, no literal `other`)
- `node_contact_confirmed`: true

Refined bridge diagnostic — same fingerprint across all 5 runs
(deterministic):

- `error_kind`: `tls_error`
- `error_sha256_12`: `affb82dc34e2`
- `raw_connect_error_sha256_12`: `65828a0ea9d6`
- `scrubbed_excerpt` (representative): `dial outbound via connect_io
  after connect error: trojan adapter uses encrypted stream for
  example.com:80; use connect_io() instead: trojan dial failed:
  Other error: TLS handshake ...`

Connect-time evidence — `connect_time_ms` per run: 684, 595, 1245,
255, 142. Pre-fix FRESH-10 connect_time_ms was 0–2ms (synchronous
local parse failure). Post-fix values reflect actual DNS resolution
+ TCP connect + TLS handshake start, confirming the runner is now
exercising real network IO before the failure.

Post-fix live signal / blocker:

- `Invalid server address` blocker is **gone**: zero occurrences in
  the new evidence (verified via `class_counts` and the redacted
  excerpts).
- New failure mode: TLS handshake to the Trojan server in
  `perform_standard_tls_handshake`. This is downstream of DNS+TCP
  and consistent across all 5 selected entries. Whether the
  underlying cause is server-side TLS (cert / SNI mismatch / not
  listening with TLS) or a Rust dataplane TLS configuration issue is
  out of scope for this round and recorded only.
- The `bridge_diagnostic.error_sha256_12` is identical across the 5
  runs, suggesting the error message tail is the same shape — likely
  a single TLS-handshake failure pattern shared by all 5 endpoints.

Next live authorization: **not needed** against the same plan /
dataplane combination. Reproducing on the same fingerprints is
deterministic. Future bounded live runs make sense only after one
of:

- A future task investigates the TLS handshake failure root cause
  (cert path / SNI / ALPN / skip_cert_verify behavior, all Rust
  dataplane work and not in scope for this round).
- A different sample with a TLS-known-good Trojan server is supplied.

No live / no node contact beyond the bounded 5-invocation reprobe.

Verification:

- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py
  scripts/tools/test_reality_clienthello_family.py
  scripts/tools/test_dual_kernel_verification.py` -> 126 PASS.
- `cargo test -p sb-adapters --features adapter-trojan --lib
  outbound::trojan::tests` -> 13 PASS.
- `cargo test -p sb-adapters --features adapter-trojan --test
  trojan_integration` -> 15 PASS, 2 ignored (pre-existing).
- `cargo check --workspace` -> PASS.
- `cargo build -p app --features router,adapters --bin probe-outbound`
  -> PASS.
- `cargo test -p app --features router,adapters --bin probe-outbound`
  -> 6 PASS.
- `git diff --check` -> clean.
- Secret scan against the 270 raw `/tmp` candidate-config positions
  (5 unique values across `server`, `password`, TLS `server_name` for
  90 normalized outbounds) — no leak in the diff, modified docs, or
  any `/tmp/trojan_*` redacted evidence (including the new r12
  artifacts).

Classification: **A — post-fix live signal; structured bridge_probe,
no tool_error, no `invalid_server_address`, refined class fully
post-DNS / post-TCP**. Rust-only quality line, BHV 52/56 unchanged.

## MT-TROJAN-FRESH-13 Trojan TLS Handshake No-Live Root Cause Audit

Date: 2026-05-07.

No live probe was authorized or run. This round audited the FRESH-12
TLS-handshake failure surface using only redacted evidence and code
review, and addressed every actionable Rust dataplane / tooling bug
that surfaced.

FRESH-12 evidence recoverability (re-read from
`/tmp/trojan_live_sanity_r12.json`):

- 5 results, all `stage=connect`, `stream_mode=connect_io`,
  `error_kind=tls_error`.
- Identical bridge fingerprints across all 5 runs:
  `error_sha256_12=affb82dc34e2`,
  `raw_connect_error_sha256_12=65828a0ea9d6`. Same TLS error tail
  shape across two distinct server hashes and five distinct ports →
  the failure is not per-endpoint.
- `connect_time_ms` distribution `[142, 255, 595, 684, 1245]` ms — all
  reflect real DNS+TCP+TLS-start, none are synchronous local failures.
- The 220-char redacted excerpt clipped at `... TLS handshake ...`, so
  the precise rustls error tail cannot be recovered from FRESH-12
  evidence alone. Source-level audit recovered the cause without
  needing a new live run.

TLS config / lowering audit (counts only, no values):

- 90/90 outbounds: `tls.enabled=true`.
- 90/90 outbounds: `tls.server_name` present (per-entry SNI).
- 0/90 outbounds: top-level `tls_sni`.
- 90/90 outbounds: `tls.insecure=true` (sing-box canonical flag).
- 0/90 outbounds: `tls.skip_cert_verify` or `tls.allow_insecure` set
  directly.
- 0/90 outbounds: top-level or `tls.alpn` set.

Pre-fix lowering at `crates/sb-config/src/validator/v2/outbound.rs:
872-877` only consulted `tls.skip_cert_verify` and
`tls.allow_insecure`, dropping `tls.insecure` on the floor. With the
fallback chain miss, `ir.skip_cert_verify` stayed `None`, and at
`crates/sb-adapters/src/register.rs:1027` it landed in
`TrojanConfig.skip_cert_verify=false`. The Trojan adapter then ran
`perform_standard_tls_handshake` with the `webpki_roots` verifier
against certs that almost certainly aren't from a public CA → every
TLS handshake failed with the same fingerprint shape FRESH-12
captured.

TLS handshake path audit
(`crates/sb-adapters/src/outbound/trojan.rs:248-308`):

- `skip_cert_verify=true` correctly installs the in-tree `NoVerifier`
  (verified by a localhost loopback test below).
- `skip_cert_verify=false` correctly uses `webpki-roots` verification.
- ALPN is only advertised when `config.alpn` is non-empty; FRESH-07
  candidates have no ALPN, so ALPN is not contributing.
- SNI fallback formerly used `config.server.split(':').next()` —
  fragile for bracketed IPv6 (`[::1]:443` would extract `[`). Not
  triggered in FRESH-07 because `register.rs:1018` always populates
  `cfg.sni`, but a latent bug worth fixing alongside FRESH-11's
  `parse_server_endpoint`.

Dataplane fixes (no-live):

1. `crates/sb-config/src/validator/v2/outbound.rs:872-878` — extend
   the fallback chain with `tls.get("insecure").as_bool()` so
   sing-box's canonical `tls.insecure=true` lowers into
   `ir.skip_cert_verify=Some(true)`.
2. `crates/sb-adapters/src/outbound/trojan.rs:286-296` — replace the
   fragile SNI fallback with `parse_server_endpoint`. Hostname /
   IPv4 / `[IPv6]` all yield a clean SNI string; otherwise fall back
   to `localhost`.

TLS diagnostic subclasses added
(`scripts/tools/trojan_probe_live.py:BRIDGE_CLASS_PATTERNS`):

- `tls_cert_unknown_issuer` — `unknownissuer` /
  `certificate signed by unknown authority` / `self-signed
  certificate` / `untrusted root`.
- `tls_name_mismatch` — `notvalidforname` / `name mismatch` /
  `subjectaltname` / `certificate not valid for name`.
- `tls_cert_expired` — `expired` cert variants.
- `tls_invalid_dns_name` — `invalid dns name` / `invalid server name`.
- `tls_alert` — `received fatal alert` / `alertdescription` /
  `alert: handshake_failure` / `alert: bad_certificate`.
- `tls_protocol_version` — `peerincompatibleerror` / `no protocols in
  common` / `unsupported protocol version`.
- `tls_handshake_failure` — `inappropriate handshake message` /
  `invalid clienthello` / `invalid serverhello` / `tls handshake
  failed` / `handshake failure`.
- Generic `tls_error` is retained as the last-resort fallback for
  unrecognized TLS text.

Root cause / remaining blocker:

- **Primary**: missing `tls.insecure` lowering — fixed.
- **Secondary**: fragile SNI fallback for bracketed IPv6 — fixed.
- **Confirmation needed via live**: whether the `tls.insecure` fix
  alone resolves the FRESH-12 `class_counts=tls_error=5`. The
  evidence chain strongly suggests yes — every candidate sets
  `tls.insecure=true`, and the post-fix `skip_cert_verify=true` path
  is verified by the loopback tests below — but ONLY a future
  authorized live reprobe can confirm it on the real sample.

No-live / no-node-contact confirmation:

- Live remains prohibited. No `probe-outbound --target` dial; no
  `trojan_probe_live.py` invocation; no node contact.
- Verification is purely synthetic / loopback: 18 Trojan unit tests
  (12 parser + 5 SNI fallback + 1 connector creation), 17 Trojan
  integration tests (15 pre-existing + 2 new TLS loopback), 11 new
  Python classifier tests for the TLS subclasses, 3 new sb-config
  lowering regression tests for `tls.insecure` /
  `tls.skip_cert_verify` / `tls.allow_insecure`.
- The TLS loopback tests use a `localhost` self-signed cert via
  `rcgen` and exercise `TrojanConnector::dial` end-to-end:
  `skip_cert_verify=true` must NOT surface any cert-verify keyword
  (proves `NoVerifier` is reached), and `skip_cert_verify=false` must
  fail with a cert-verify keyword (proves the strict path is
  reachable and not silently bypassed).

Future live authorization: yes, justified to confirm the FRESH-12
`tls_error=5` shape resolves under the FRESH-13 lowering fix. The
deterministic local cause is fixed; only a live reprobe can prove
the remote node behavior on the existing 5-tag bounded plan.

Verification:

- `python3 -B -m unittest test_reality_probe_tools
  test_reality_clienthello_family test_dual_kernel_verification` ->
  137 PASS.
- `cargo test -p sb-adapters --features adapter-trojan --lib
  outbound::trojan::tests` -> 18 PASS.
- `cargo test -p sb-adapters --features adapter-trojan --test
  trojan_integration` -> 17 PASS, 2 ignored (pre-existing).
- `cargo check --workspace` -> PASS.
- `cargo build -p app --features router,adapters --bin probe-outbound`
  -> PASS.
- `cargo test -p app --features router,adapters --bin probe-outbound`
  -> 6 PASS.
- `git diff --check` -> clean.
- Secret scan against the 270 raw `/tmp` candidate-config positions
  (5 unique values across 90 outbounds) — no leak in the diff,
  modified Rust sources, Python tooling, agent docs, or any
  `/tmp/trojan_*` redacted evidence.

Classification: **A — root cause located; two no-live dataplane /
tooling fixes plus eight new TLS diagnostic subclasses; ready for a
future authorized live reprobe**. Rust-only quality line, BHV 52/56
unchanged.

## MT-TROJAN-FRESH-14 Post-TLS-Fix Bounded Trojan Live Reprobe

Date: 2026-05-07.

Authorization was explicitly limited to one bounded reprobe of the
existing FRESH-07 normalized config, the existing bounded plan, and
the FRESH-13 lowering / SNI / classifier fixes. No REALITY live, no
sampler/dataplane modification, no sample expansion, no live
authorization expansion.

Pre-gate (`./target/debug/probe-outbound --validate-config-only
--json` per selected tag):

- normalizer rerun: `outbounds_count=90`, `__id_in_gui=90` removed,
  `ready_for_no_dial_preflight=true`; SHA-256 of normalized JSON
  identical to existing `/tmp/mt_trojan_fresh_config_normalized.json`.
- intake rerun: `trojan_ready=88`, `duplicate=2`, `not_ready=0`,
  `unsupported=0`.
- plan re-verified identical to existing
  `/tmp/trojan_probe_plan.json` — same 5 server/password/server_name/
  port fingerprints, no sample re-selection, summary equality holds.
- preflight: `preflight_invocations=5`, `passed_count=5`,
  `failed_count=0`, `no_network=true` x5, `outbound_type=trojan` x5,
  `selected_found=true` x5, `bridge_member_found=true` x5,
  `node_contact_confirmed=false`.
- TLS lowering counts on normalized config: `tls.enabled=true` x90,
  `tls.server_name` present x90, `tls.insecure=true` x90,
  `tls.skip_cert_verify=true` x0, `tls.allow_insecure=true` x0 →
  every selected outbound goes through the FRESH-13 fallback chain
  into `ir.skip_cert_verify=true` and reaches `NoVerifier`.

Bounded live reprobe:

- plan: `/tmp/trojan_probe_plan.json`
- candidate config: `/tmp/mt_trojan_fresh_config_normalized.json`
- target: `example.com:80`, timeout: 8, runs: 1, planned_runs: 5
- redacted evidence: `/tmp/trojan_live_sanity_r14.json`,
  `/tmp/trojan_live_sanity_r14.md`

Live summary:

- `classification`: A
- `executed_runs`: 5
- `ok_count`: 5
- `failed_count`: 0
- `env_limited_count`: 0
- `tool_error_count`: 0
- `status_counts`: `ok=5`
- `class_counts`: `{}` (no `tls_error`, no `tls_*` subclass, no
  `invalid_server_address`, no `unsupported_protocol`, no literal
  `other`)
- `node_contact_confirmed`: true

Per-run signal (sorted by run index):

- run 0: `connect_time_ms=523`, `response_bytes=832`,
  `first_line=HTTP/1.1 200 OK`, `stream_mode=connect_io`, `rc=0`.
- run 1: `connect_time_ms=567`, `response_bytes=836`,
  `first_line=HTTP/1.1 200 OK`, `stream_mode=connect_io`, `rc=0`.
- run 2: `connect_time_ms=241`, `response_bytes=835`,
  `first_line=HTTP/1.1 200 OK`, `stream_mode=connect_io`, `rc=0`.
- run 3: `connect_time_ms=264`, `response_bytes=833`,
  `first_line=HTTP/1.1 200 OK`, `stream_mode=connect_io`, `rc=0`.
- run 4: `connect_time_ms=159`, `response_bytes=832`,
  `first_line=HTTP/1.1 200 OK`, `stream_mode=connect_io`, `rc=0`.

Post-TLS-fix live signal / blocker:

- The FRESH-12 `class_counts=tls_error=5` fingerprint
  (`error_sha256_12=affb82dc34e2`) is **fully cleared**. Zero TLS
  failures across 5 runs / 2 distinct server hashes / 5 distinct
  ports. The FRESH-13 root cause analysis (missing `tls.insecure`
  lowering) is confirmed empirically — flipping the lowering chain
  alone moved every selected entry from synchronous TLS-handshake
  failure to full end-to-end Trojan tunnel success on the same
  server-side state, the same plan, the same dataplane.
- The probe goes all the way through DNS resolution, TCP connect,
  TLS handshake (skip_cert_verify path), Trojan auth, target
  CONNECT to `example.com:80`, HTTP request, and HTTP response
  read (~832-836 bytes including the `HTTP/1.1 200 OK` first line).
- No remaining TLS failure to subclass under FRESH-13's
  `tls_cert_unknown_issuer` / `tls_name_mismatch` / etc.

Tooling cosmetic (recorded only, not fixed this round):

- `bridge_diagnostic.error_kind` is emitted as `unsupported_protocol`
  on every successful run, even though `bridge_probe.error=None`
  (`error_sha256_12=None`). The classifier always assigns a label
  when the connect / connect_io chain carries the expected wrapper
  rejection text `uses encrypted stream` (which is the runner's
  signal that it correctly fell back to `connect_io`). This is a
  classifier should-be-skipped-on-success cosmetic, not a regression
  and not a node-quality conclusion. The success signal is in
  `status=ok`, `ok=true`, `class=None`, `connect_time_ms`,
  `response_bytes`, and the stdout `OK ...` excerpt.

Next live authorization: **not needed** against the same plan /
dataplane combination — the reprobe is now deterministically
successful and reproducing it would just consume node bandwidth.
Future bounded live runs only make sense for new investigations
(e.g., UDP relay path, non-CONNECT targets, ALPN variants), each
under a separate explicit authorization. Live remains otherwise
prohibited.

Verification:

- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py
  scripts/tools/test_reality_clienthello_family.py
  scripts/tools/test_dual_kernel_verification.py` -> 137 PASS.
- `cargo test -p sb-adapters --features adapter-trojan --lib
  outbound::trojan::tests` -> 18 PASS.
- `cargo test -p sb-adapters --features adapter-trojan --test
  trojan_integration` -> 17 PASS, 2 ignored (pre-existing).
- `cargo test -p sb-config tls_insecure` -> 2 PASS (FRESH-13
  lowering regressions).
- `cargo check --workspace` -> PASS.
- `cargo build -p app --features router,adapters --bin probe-outbound`
  -> PASS.
- `cargo test -p app --features router,adapters --bin probe-outbound`
  -> 6 PASS.
- `git diff --check` -> clean.
- Secret scan against the 5 unique raw `/tmp` candidate-config
  values (270 positions across `server`, `password`, TLS
  `server_name` for 90 normalized outbounds) — no leak in the
  diff, modified docs, or any `/tmp/trojan_*` redacted evidence
  (including the new r14 artifacts).

Classification: **A — post-TLS-fix live signal: structured
bridge_probe, no `tool_error`, no TLS subclass, no literal
`other`, full end-to-end Trojan success on all 5 selected
entries**. Rust-only quality line, BHV 52/56 unchanged.

## MT-TROJAN-FRESH-15 Success Evidence Hygiene + Line Closure

Date: 2026-05-07.

No live probe was authorized or run. This round addresses only the
FRESH-14 success-evidence cosmetic and formally closes the
MT-TROJAN-FRESH line for the bounded plan reused since FRESH-04.

Cosmetic fix (`scripts/tools/trojan_probe_live.py`):

- `result_from_probe` now short-circuits on `bridge_probe.ok=true`:
  `class=None`, `bridge_diagnostic=None`. The wrapper-rejection text
  in `raw_connect_error` (`uses encrypted stream ... use connect_io()
  instead`) is the EXPECTED runner breadcrumb that the bridge layer
  routed via `connect_io`. Running `BRIDGE_CLASS_PATTERNS` against
  that breadcrumb on a successful run mislabeled
  `bridge_diagnostic.error_kind=unsupported_protocol` even though
  there was no actual error (`bridge_probe.error=None`). This was
  cosmetic only — `class_counts` already excluded it (`item.get
  ("class")` was `None`) — but the per-result diagnostic block
  surfaced it in redacted MD/JSON.
- `render_redacted_md` continues to skip the bridge block when
  `bridge_diagnostic` is `None`; success runs now omit
  `bridge_error_kind`, `bridge_fingerprint`, and `bridge_excerpt`
  entirely. The success record retains `status: ok`, `class: None`,
  `stream_mode`, plus the tool diagnostic excerpt with the
  redacted `OK ... HTTP/1.1 200 OK` breadcrumb.
- The failure path is unchanged: `bridge_diagnostic_for_probe` still
  runs when `ok=false`, refined classes
  (`unsupported_protocol`, `dns_error`, `tls_error`,
  `tls_cert_unknown_issuer`, `invalid_server_address`, etc.) still
  apply, and the `connect_io` raw_connect_error breadcrumb still
  contributes to refinement.

Tests added under `TrojanProbeLiveTests`:

- `test_fake_structured_probe_success_keeps_classification_a`:
  fixed (was a noop ternary). Now asserts
  `result["bridge_diagnostic"] is None` on success.
- `test_fresh15_success_with_wrapper_rejection_hint_has_no_diagnostic`:
  injects the FRESH-14 wrapper-rejection text into a successful
  `bridge_probe`, asserts `class=None`, `bridge_diagnostic=None`,
  and that `connect_time_ms`/`response_bytes` survive.
- `test_fresh15_success_class_counts_stay_empty`: end-to-end summary
  on a single successful run yields `class_counts={}`,
  `status_counts={ok:1}`, `classification=A`.
- `test_fresh15_success_redacted_md_omits_bridge_diagnostic`: the
  rendered MD must NOT contain `bridge_error_kind`,
  `bridge_fingerprint`, `bridge_excerpt`, or the `unsupported_protocol`
  cosmetic; success record still shows `status: ok`, `class: None`,
  `stream_mode: connect_io`.
- `test_fresh15_failure_path_still_emits_refined_diagnostic`:
  regression guard — a failure with TLS-unknown-issuer text still
  produces `class=tls_cert_unknown_issuer` and a non-null
  `bridge_diagnostic` with a 12-char `error_sha256_12`.
- `test_fresh15_success_does_not_leak_raw_secrets_in_evidence`:
  even when a future runtime leaks a server name into the
  `raw_connect_error` of a successful probe, the success
  short-circuit keeps the standard scrub contract — neither MD nor
  JSON contain the raw value, and `bridge_diagnostic` stays None.

FRESH-14 evidence rederivation (no live, redacted only):

- source: `/tmp/trojan_live_sanity_r14.json`
  (sha256[:12]=`04f119f59e89`)
- plan: selected_count=5, runs=1, target=`example.com:80`,
  timeout=8, planned_runs=5
- live outcome: executed_runs=5, ok_count=5, failed_count=0,
  tool_error_count=0, env_limited_count=0,
  status_counts={ok:5}, class_counts={},
  node_contact_confirmed=true
- per-run connect_time_ms (sorted): [159, 241, 264, 523, 567]
- per-run response_bytes (sorted): [832, 832, 833, 835, 836]
- unique server hashes (sha256[:12]): 2
  (`232448171a6a`, `27439776c9b0`)
- unique ports across selected: 5

MT-TROJAN-FRESH line closure status:

- The R72c Trojan sample intake → normalize → no-dial preflight →
  refined classifier → hostname dataplane fix → TLS lowering
  fix → bounded live reprobe arc reaches a 5/5 successful Trojan
  tunnel against the same bounded plan. **No further live is
  needed against this plan/dataplane combination.**
- The bounded 5x1 plan, the FRESH-07 normalized config, and the
  selected 5 fingerprints are stable. They remain available for a
  future authorized re-validation if a regression is suspected,
  but routine maintenance does not require running them.
- A new bounded live authorization is required for any of the
  following distinct quality lines (each its own task):
  - UDP relay path (`udp_relay_dial`) — pre-existing limitation
    around IPv6 ATYP encoding noted in FRESH-11; not reproduced
    by FRESH-14's TCP-only target.
  - ALPN advertising — FRESH-07 sample has empty ALPN; behavior
    under ALPN-required Trojan servers is untested.
  - Non-CONNECT targets (UDP, mux, h2/grpc transports).
  - A new sample with a TLS-trusted Trojan server to exercise
    `skip_cert_verify=false` end-to-end.

No-live / no-node-contact confirmation:

- Live remains prohibited and was not exercised in FRESH-15. No
  `probe-outbound --target` dial. No `trojan_probe_live.py` live
  invocation. No node contact. The cosmetic was verified with the
  existing 5 unit tests above plus the larger TrojanProbeLive test
  class.

Verification:

- `python3 -B -m unittest scripts/tools/test_reality_probe_tools.py
  scripts/tools/test_reality_clienthello_family.py
  scripts/tools/test_dual_kernel_verification.py` -> **142 PASS**
  (was 137; +5 FRESH-15 success-hygiene tests).
- `cargo test -p sb-adapters --features adapter-trojan --lib
  outbound::trojan::tests` -> **18 PASS**.
- `cargo test -p sb-adapters --features adapter-trojan --test
  trojan_integration` -> **17 PASS, 2 ignored** (pre-existing).
- `cargo test -p sb-config tls_insecure` -> **2 PASS**.
- `cargo check --workspace` -> PASS.
- `cargo build -p app --features router,adapters --bin probe-outbound`
  -> PASS.
- `cargo test -p app --features router,adapters --bin probe-outbound`
  -> 6 PASS.
- `git diff --check` -> clean.
- Secret scan against the 5 unique raw `/tmp` candidate-config
  values (270 positions across `server`, `password`, TLS
  `server_name` for 90 normalized outbounds) — no leak in the
  diff, modified Python tooling, modified test source, or any
  `/tmp/trojan_*` redacted evidence.

Classification: **A — no-live; success-evidence cosmetic fixed,
failure-path refinement preserved, MT-TROJAN-FRESH line closed
on the bounded plan**. Rust-only quality line, BHV 52/56 unchanged.
