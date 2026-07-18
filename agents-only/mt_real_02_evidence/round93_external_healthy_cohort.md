<!-- tier: C -->
# R93 External Healthy Cohort — PASS, Banked At Depth 3

Date: 2026-07-19

## Scope

- Source: user-supplied GUI subscription snapshot, modified 2026-07-18 23:47 +08:00;
  source SHA-256 `0f40004fc36a6ab17cb664f30f7a205b5330b7396d66002d1866c7e07e94b6b9`.
- Source contained 19 VLESS+REALITY plain-TCP Vision entries. Converted probe config SHA-256:
  `0e4650ab2078e9f902a8f1205a02e2eb02f2798a650588dd70f9481556634d3d`.
- Raw UUIDs, endpoints, public keys, and short IDs stayed in local temporary inputs and were
  never committed. Durable evidence uses neutral node IDs only.
- Intake: 19 fresh-ready, zero duplicate, zero not-ready, zero covered-existing. Production
  config parse passed. R81 checked all 19 outbounds with zero schema violation.

## Screening And Chain Discipline

- An earlier public-aggregate cohort failed confirmation and was discarded before this
  user-supplied snapshot became the current target. Its results are not counted in this record.
- Initial 19-node discovery: 18 `all_ok`; one matrix timeout. No timed-out node entered the
  formal cohort.
- First fixed cohort (`006/009/012`): round 1 was 9/9 `all_ok`; round 2 had one
  `bridge_io_diverged` connection reset on `012`. Entire chain was discarded.
- Seven alternate servers then received three qualification runs each. Six were 3/3 `all_ok`;
  one showed a connection-reset divergence and was rejected.
- Final fixed cohort used three distinct servers: `006/009/014`. Its R81 dry-run passed before
  live execution. No node was replaced inside the accepted chain.

## Accepted Observation

| Consecutive round | Matrices | Labels | Phase classes | Matrix timeout |
|---|---:|---|---|---|
| 1 | 9/9 completed | 9 `all_ok` | 81 `ok` | no |
| 2 | 9/9 completed | 9 `all_ok` | 81 `ok` | no |
| 3 | 9/9 completed | 9 `all_ok` | 81 `ok` | no |

Total: 27/27 matrices completed, 27/27 `all_ok`, 243/243 phase classifications `ok`, zero
same-failure, zero divergence, zero matrix error, zero timeout. Verdict: **PASS**, banked at
consecutive depth 3 under golden-spec S4 §F.

Machine-readable record:
`agents-only/mt_real_02_evidence/round93_external_healthy_cohort.json`.

## Verification

- External-observation schema/semantic validator — PASS.
- `python3 scripts/tools/test_reality_probe_tools.py` — PASS.
- `make verify-reality-local` — PASS.
- Boundaries, consistency, diff check, and evidence-secret scan — PASS in accepting commit.

## Non-Claims

- Observation remains pre-release and non-gating; public-node liveness may drift.
- Real-network camouflage sufficiency remains open.
- Success-path ServerHello byte borrowing remains rustls ARCH-LIMIT.
- No dual-kernel `52/56` BHV movement.
