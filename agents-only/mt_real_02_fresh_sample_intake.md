<!-- tier: A -->
# MT-REAL-02 Fresh Sample Intake — Operator Guide

> R71 deliverable. Read before producing the next REALITY/VLESS sample
> face for MT-REAL-02 stage-3 path A.

The committed sample face in
`agents-only/mt_real_01_evidence/phase3_ip_direct.json` is now closed
(R70 / closure_report addendum). Any further sampler/dataplane signal
hunt requires a *fresh* config. This document describes how to feed
that fresh config through the intake validator without leaking secrets
and without touching the committed baseline.

---

## 1. What the validator needs

`scripts/tools/reality_vless_sample_intake.py` accepts a candidate
sing-box config and three reference inputs:

| Argument | Purpose |
|---|---|
| `--candidate-config PATH` | The new config you want to bring in. |
| `--baseline-config PATH` | Existing committed sample face. Default: `agents-only/mt_real_01_evidence/phase3_ip_direct.json`. |
| `--rollup-json PATH` | Existing live rollup. Default: `agents-only/mt_real_02_evidence/live_rollup.json`. |
| `--output-json PATH` | Where to write the redacted classification result. |
| `--redacted-md PATH` | (optional) Human-readable redacted summary. |

The validator does **not** open any network connection. It only parses
the candidate config, compares it to the committed baseline by
fingerprint, and cross-checks against the rollup index.

---

## 2. Required fields per candidate VLESS outbound

For every outbound that should be picked up as REALITY-ready, the
config block must contain:

- `type: "vless"`
- `tag` (or `name`)
- `server` and `server_port` (or `port`)
- `uuid`
- `tls.reality.public_key` (or top-level `reality_public_key`)
- `tls.server_name` / `tls.reality.server_name` / `reality_server_name`
  / `tls_sni` (any one)
- plain-TCP transport (no `transport` field, or `transport: { type: "tcp" }`)

Anything missing puts the outbound in the `not_ready` bucket with a
specific `skip_reason` (`missing_uuid`,
`missing_reality_public_key`, etc.).

`short_id` and `utls.fingerprint` are not required for readiness, but
are part of the fingerprint signature used for duplicate detection —
include them if you have them so duplicates are not missed.

---

## 3. Classification buckets

| Bucket | Meaning |
|---|---|
| `fresh_ready` | Passes readiness check, tag is new, fingerprint is new, rollup has no entry under the stripped tag. **Eligible for R72 live probe.** |
| `duplicate` | Tag collision with the committed baseline (`duplicate_kind=tag`) or fingerprint collision under a different tag (`duplicate_kind=fingerprint`). |
| `not_ready` | One or more REALITY/VLESS fields missing. Returned with the specific `skip_reason`. |
| `covered_existing` | Ready and not a tag/fingerprint duplicate, but the (suffix-stripped) tag already appears as a rollup key — this candidate would just rerun an existing rollup line. |

`summary.ready_for_r72` is true iff `fresh_ready` is non-empty. R72
must not start without that flag being true on the produced JSON.

---

## 4. Hard rules for the operator

- **Never commit raw secrets.** Validator output is redacted by
  design; if you produce a custom report, do not add UUIDs, public
  keys, short_ids, or full server addresses to anything tracked by
  git.
- **Never edit the committed baseline.**
  `agents-only/mt_real_01_evidence/phase3_ip_direct.json` is the
  reference face. Add the new config as a new file, e.g.
  `/tmp/mt_real_02_fresh_config.json`.
- **Never run a live probe before intake passes.** The R72 live round
  must consume the JSON produced by this validator and operate only on
  outbounds in `fresh_ready`.
- **Never disable redaction.** If the validator output ends up not
  redacted, treat that as a bug and fix it.

---

## 5. Operator runbook (next round)

Step 1. Place the candidate config at a path *outside* `agents-only/`,
e.g. `/tmp/mt_real_02_fresh_config.json`. This avoids any chance of
the raw config sneaking into git.

Step 2. Run the validator:

```bash
python3 scripts/tools/reality_vless_sample_intake.py \
  --candidate-config /tmp/mt_real_02_fresh_config.json \
  --baseline-config agents-only/mt_real_01_evidence/phase3_ip_direct.json \
  --rollup-json agents-only/mt_real_02_evidence/live_rollup.json \
  --output-json /tmp/mt_real_02_fresh_intake.json \
  --redacted-md /tmp/mt_real_02_fresh_intake.md
```

Step 3. Inspect `summary.counts` and `summary.ready_for_r72`. If
`ready_for_r72` is `false`, do **not** advance to R72 — fix the
candidate config and rerun step 2.

Step 4. With `ready_for_r72=true`, hand the JSON to the planner for a
dry-run only:

```bash
python3 scripts/tools/reality_vless_probe_batch.py \
  --config /tmp/mt_real_02_fresh_config.json \
  --outbound '<one fresh_ready tag>' \
  --runs 4 --target example.com:80 \
  --timeout 8 --phase-timeout-ms 8000 --probe-io-timeout-ms 8000 \
  --output-dir /tmp/reality-vless-probe-batch-dryrun-fresh \
  --dry-run
```

Step 5. Only after a clean dry-run drop the `--dry-run` flag. That is
R72 stage-2 (live), out of scope for R71.

---

## 6. Intake output schema (redacted)

`output-json` shape:

```json
{
  "summary": {
    "total_vless_outbounds": <int>,
    "counts": {
      "fresh_ready": <int>,
      "duplicate": <int>,
      "not_ready": <int>,
      "covered_existing": <int>
    },
    "selected_count": <int>,
    "ready_for_r72": <bool>
  },
  "fresh_ready": [ { "tag": ..., "region": ..., "fingerprint": {...} }, ... ],
  "duplicate":   [ ... ],
  "not_ready":   [ ... ],
  "covered_existing": [ ... ]
}
```

`fingerprint` only contains 12-char SHA-256 prefix hashes of the raw
secret material plus the public, non-secret port and `server_name`.
That keeps duplicate-detection deterministic without storing any
recoverable account material.

---

## 7. R71 status snapshot

- Validator: implemented (`scripts/tools/reality_vless_sample_intake.py`).
- Tests: 7 unit tests under
  `scripts/tools/test_reality_probe_tools.py::RealityVlessSampleIntakeTests`.
- Live probe: not run.
- Sampler/dataplane: not modified.
- Fresh config supplied this round: **none**. The next round (R72)
  cannot start until the operator drops a candidate config at the
  path documented in step 1 above.
