<!-- tier: B -->
# MT-MIXED-FRESH-01 — Mixed Fresh Config Intake + Protocol Split (no-live)

> Read-only static analysis of a candidate config containing 32 mixed
> outbounds (20 vless + 12 hysteria2). Live probing is NOT authorised
> by this task. No real node was contacted. Sampler/dataplane were
> not modified. `go_fork_source/*` was not modified. `.github/workflows/*`
> was not modified. BHV must remain 52/56 — this work is Rust-only
> intake quality, not dual-kernel parity.

## Inputs (not committed)

- Candidate (root=list): `/tmp/mt_mixed_fresh_config.json`
- Wrapped (root=object): `/tmp/mt_mixed_fresh_config_wrapped.json`
- Per-protocol subsets: `/tmp/mt_mixed_fresh_subset_{reality,ws,hys2}.json`
- All `/tmp` files contain raw secrets and are excluded from the commit.

## Committed redacted artefacts

- `agents-only/mt_mixed_fresh_evidence/triage.json`
- `agents-only/mt_mixed_fresh_evidence/reality_intake.json`
- `agents-only/mt_mixed_fresh_evidence/reality_intake.md`
- `agents-only/mt_mixed_fresh_evidence/hysteria2_audit.json`
- `agents-only/mt_mixed_fresh_evidence/ws_xhttp_audit.json`
- `agents-only/mt_mixed_fresh_evidence/dry_run_plan.json`

All committed artefacts hash UUIDs, server addresses, public_keys,
short_ids, server_names, tags, paths, and Host header values. Ports
and uniform-value distribution counts are kept because they are not on
this task’s no-leak list and are needed to disambiguate duplicates.

## Classification

- total_outbounds: 32
- type_counts: vless=20, hysteria2=12
- transport_counts: absent=27, ws=5
- websocket_transport_count: 5
- xhttp / httpupgrade / grpc / h2 / quic transport counts: 0 / 0 / 0 / 0 / 0
- All required fields present: vless_uuid 0 missing, hys2_password 0 missing,
  reality_public_key 0 missing on the 15 reality vless, server / server_port
  0 missing across the batch.

## Protocol split

| Line | Count | Eligibility for this task |
|------|-------|---------------------------|
| REALITY/VLESS (TCP) | 15 | enters REALITY intake |
| Plain VLESS+WS+TLS  | 5  | enters WS compat audit only |
| Hysteria2           | 12 | enters readiness audit only |
| Other               | 0  | n/a |

The three lines are accounted separately. The 5 plain-VLESS+WS nodes
are NOT counted in REALITY accounting and are NOT counted in
hysteria2 accounting.

## REALITY/VLESS intake (15 candidates)

Reused `scripts/tools/reality_vless_sample_intake.py` against the
default committed baseline (`agents-only/mt_real_01_evidence/phase3_ip_direct.json`)
and rollup (`agents-only/mt_real_02_evidence/live_rollup.json`).
Counts:

- fresh_ready: 15
- duplicate: 0
- not_ready: 0
- covered_existing: 0
- ready_for_r73: **true** (gate satisfied: fresh_ready > 0)

The intake JSON / MD have been re-redacted on top of the script’s
default output to additionally hash `tag`, `region`, and every
top-level + nested `server_name`, since this task’s constraints add
those to the no-leak list.

## Hysteria2 readiness audit (12 candidates)

- ready: 12
- not_ready: 0
- duplicate_in_batch: 0
- All 12 carry `password`, `server`, `server_port`, `tls.enabled=true`,
  `tls.server_name`. All 12 set `tls.insecure=true`.
- None carry `obfs`, `up_mbps`, `down_mbps`, `salamander`, or `brutal`.

Tooling gap: there is no `hysteria2_sample_intake.py`,
`hysteria2_probe_plan.py`, or `hysteria2_probe_live.py` in
`scripts/tools/`. No live tool is built, none is created in this
task, and no live run is planned. Validator v2 supports every
hys2 field present in this candidate set.

## WS / XHTTP / HTTPUpgrade compatibility audit (5 ws candidates)

| Field | Status | Notes |
|-------|--------|-------|
| `transport.ws.path` | supported | `parse_transport_object` → `OutboundIR.ws_path` → `WebSocketTransportConfig.path` |
| `transport.ws.headers.host` | supported | extracted to `OutboundIR.ws_host` and re-emitted as a `Host` header in `register.rs::build_transport_config` |
| `transport.ws.max_early_data` | **silently dropped** | not read in `parse_transport_object`; no IR field; `transport_config.rs:222-224` hardcodes 0. 5/5 nodes set `2048`; effective behaviour: early data disabled. |
| `transport.ws.early_data_header_name` | **silently dropped** | same chain. 5/5 nodes set a 22-char header name (matches the hardcoded default `Sec-WebSocket-Protocol`), so the silent drop has no effective behaviour change for this batch. |
| `transport.xhttp.*` | unsupported in validator | not relevant for this batch (0 xhttp). |
| `transport.httpupgrade.*` | supported | not relevant for this batch (0 httpupgrade). |

Field normalization recommendations (for a future authorised task,
not this one): extend `parse_transport_object` to read
`max_early_data` and `early_data_header_name`; add matching
`OutboundIR.ws_max_early_data` and `OutboundIR.ws_early_data_header_name`
fields; plumb both via `WebSocketTransportConfig` in
`register.rs::build_transport_config`; remove the hardcodes at
`transport_config.rs:222-224`. These changes are dataplane-shaping
and are out of scope here.

## Dry-run plan summary

15 vless+reality candidates would form a planned R73-style live round
of 5 runs each → 75 total runs targeted at `example.com:80` per the
existing R71 plan template. **No live run was executed.** Gates that
must clear before any live attempt: separate user authorization,
pre-gate 5/5 no_network sanity, BHV unchanged at 52/56, fresh_ready
unchanged at 15, no leaked material in any redacted artifact.

## No-live / no-node-contact confirmation

- No process invoked any live probe tool.
- No socket was opened to any candidate `server`.
- `agents-only/mt_real_02_evidence/live_rollup.json` is unmodified.
- No new entry added to `agents-only/mt_real_02_evidence/`.
- BHV count remains 52/56 (this task did not touch dual-kernel parity).

## R73 outcome (2026-05-08, post-authorization; restated by R74 audit)

Live executed under the dry-run plan above:

- executed_runs: 75 / 75
- run-level: run_all_ok=46, run_divergence=2, run_same_failure=27
- divergence_phase_label_count (occurrences) = 5; distinct = 4
- 9 fresh outbounds reached 5/5 run_all_ok end-to-end (fresh01,
  fresh08–fresh15)
- fresh06: 1 run_all_ok + 1 run_divergence + 3 run_same_failure;
  the single divergence run carries 3 phase labels (app_minimal +
  bridge_io + minimal_transport) — first MT-REAL-02 single-run
  all-three-phase carrier; still inside existing taxonomy
- fresh02: 1 run_divergence + 4 run_same_failure (timeout); the
  single divergence run carries 2 phase labels
  (app_pre_post + app_minimal) plus probe_io_all_other on the
  same run — node-health limited
- fresh03/04/05/07: 5/5 run_same_failure each
- probe_io vs reality run-level fates aligned ±1; no transport-vs-app
  new class
- Hys2 / WS / plain-VLESS live: 0 runs each (not authorized)
- BHV 52/56 unchanged

Evidence:
`agents-only/mt_real_02_evidence/round73_mixed_fresh_live_summary.{json,md}`
and the regenerated rollup
`agents-only/mt_real_02_evidence/live_rollup.{json,md}`.
The R74 audit (2026-05-08) replaced the earlier wording that
conflated "divergence runs" with "phase-label occurrences"; the
underlying live data and the rollup tool are unchanged.
