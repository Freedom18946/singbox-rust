<!-- tier: B -->
# A4.2A Report — Historical → External-Observation Projection

Read-only spike. Targets **R82** and **R91**. Conclusion up front: **neither is
promotable; both are `PARTIAL` with `canonical_candidate = null`.** No historical
round in the corpus can be cleanly promoted, because a small set of canonical
required fields has no honest historical source on *any* round.

Provenance vocabulary and rules: see `README.md`. A field is **promotion-eligible**
iff `DIRECT` or `DERIVED_DETERMINISTIC`; the rest (`DERIVED_HEURISTIC`,
`SYNTHETIC_PLACEHOLDER`, `MISSING`) **block** promotion.

---

## R82 — `round82_fresh04_recheck_summary.json`

- Epoch: `R82_R84_SUBSET_GATE_PHASE_PROBE`. Single node `fresh04`, 3 runs, all
  `run_same_failure(timeout)`; uniform same-class (`reality_all_timeout` ==
  `probe_io_all_timeout`) ⇒ **infrastructure-dead**.
- Has: `pre_gate.subset_schema_gate{passed,violations}` (DIRECT), `pre_gate.intake_counts`
  (DIRECT), **`phase_probe_supporting_evidence.per_run[].{axis}.ok`** (DIRECT phase axes).
- Lacks: any per-run integer `matrix_status` (all `null`), any recovery-chain depth.

### R82 field provenance

| provenance | canonical fields |
|---|---|
| **DIRECT** | `round_id`; `run_plan.{subset_schema_gate_passed, violations, planned_node_ids}`; `intake_counts.{fresh_ready,covered_existing,duplicate,not_ready}`; `nodes[].node_id`; **`nodes[].{direct_reality,transport_reality,vless_dial,vless_probe_io}`** (phase-probe); `summary.{run_same_failure,run_divergence}` |
| **DERIVED_DETERMINISTIC** | `schema_version`; `observation_id`; `cohort_id` (S4§F bucket=same-failure); `verdict` (INCONCLUSIVE/infra-dead); `notes`; `run_plan.no_silent_expansion`; `nodes[].{infra_health,phase_class,included_in_client_verdict,exclusion_reason,replacement_for,replacement_reason,credential_present,config_parse_ok}`; `summary.{run_all_ok,matrix_timeout,healthy_node_count,excluded_infra_dead_count,banked,source_threshold_note}` |
| **DERIVED_HEURISTIC** | `nodes[].tcp_reachable`; `nodes[].reality_dest_usable` |
| **SYNTHETIC_PLACEHOLDER** | `timestamp` (date→midnight); `config_fingerprint` (gitrev proxy) |
| **MISSING** | `summary.matrix_status` (no per-run int; not invented); `summary.consecutive_all_ok_rounds` (no recovery field, no `--rollup`) |

### R82 `projection_status = PARTIAL` — minimal promotion-blocking set (6)

```
config_fingerprint                      SYNTHETIC_PLACEHOLDER  (universal)
timestamp                               SYNTHETIC_PLACEHOLDER  (universal)
nodes[].tcp_reachable                   DERIVED_HEURISTIC      (universal: not observed)
nodes[].reality_dest_usable             DERIVED_HEURISTIC      (universal: not observed)
summary.matrix_status                   MISSING                (no per-run int exit status)
summary.consecutive_all_ok_rounds       MISSING                (single round; pass --rollup to lift)
```

**Teaching point:** R82 *has* the hard-to-get part (DIRECT per-node phase axes from
the phase probe) yet is still blocked — chiefly by the universal synthetic/heuristic
fields and the absence of an integer matrix exit status.

---

## R91 — `round91_fresh13_round3_closure_summary.json`

- Epoch: `R89_R91_MATRIX_STATUS_OBJECT`. Single node `fresh13`, 3/3 `run_all_ok`,
  per-rep recovery closure (consecutive=3). **Looks PASS-able.**
- Has: per-run integer `matrix_status` `[0,0,0]` ⇒ `summary.matrix_status`
  DERIVED_DETERMINISTIC (the top-level `matrix_status` *object* is redundant here);
  embedded recovery depth ⇒ `consecutive_all_ok_rounds` DIRECT (=3).
- Lacks: **any `phase_probe_supporting_evidence`** ⇒ the four canonical phase
  booleans could only come from a label→phase heuristic, which is forbidden for
  canonical.

### R91 field provenance

| provenance | canonical fields |
|---|---|
| **DIRECT** | `round_id`; `run_plan.{subset_schema_gate_passed,violations,planned_node_ids}`; `intake_counts.*`; `nodes[].node_id`; `summary.{run_same_failure,run_divergence}`; **`summary.consecutive_all_ok_rounds`** (recovery field=3) |
| **DERIVED_DETERMINISTIC** | `schema_version`; `observation_id`; `cohort_id`; `verdict` (PASS); `notes`; `run_plan.no_silent_expansion`; `nodes[].{infra_health(healthy),phase_class(null),included_in_client_verdict,exclusion_reason,replacement_for,replacement_reason,credential_present,config_parse_ok}`; `summary.{run_all_ok,matrix_status(0 from per-run ints),matrix_timeout,healthy_node_count,excluded_infra_dead_count,banked}`; `summary.source_threshold_note` |
| **DERIVED_HEURISTIC** | **`nodes[].{direct_reality,transport_reality,vless_dial,vless_probe_io}`** (no phase-probe); `nodes[].tcp_reachable`; `nodes[].reality_dest_usable` |
| **SYNTHETIC_PLACEHOLDER** | `timestamp`; `config_fingerprint` |
| **MISSING** | — |

### R91 `projection_status = PARTIAL` — minimal promotion-blocking set (8)

```
config_fingerprint                      SYNTHETIC_PLACEHOLDER  (universal)
timestamp                               SYNTHETIC_PLACEHOLDER  (universal)
nodes[].tcp_reachable                   DERIVED_HEURISTIC      (universal: not observed)
nodes[].reality_dest_usable             DERIVED_HEURISTIC      (universal: not observed)
nodes[].direct_reality                  DERIVED_HEURISTIC      (no per-run phase-probe)
nodes[].transport_reality               DERIVED_HEURISTIC      (no per-run phase-probe)
nodes[].vless_dial                      DERIVED_HEURISTIC      (no per-run phase-probe)
nodes[].vless_probe_io                  DERIVED_HEURISTIC      (no per-run phase-probe)
```

**Teaching point:** a 3/3 `all_ok` PASS-able round is **NOT** auto-promotable. It
has the integer matrix status and the recovery chain R82 lacks, but it has **no
DIRECT per-node phase booleans** — the very axes the canonical `nodes[]` is built
around — plus the universal synthetic/heuristic fields.

---

## The R82 ⊕ R91 contrast (the core result)

| canonical field group | R82 | R91 |
|---|---|---|
| per-node phase axes | **DIRECT** (phase-probe) | DERIVED_HEURISTIC (none) |
| `summary.matrix_status` (int) | MISSING (no per-run int) | **DERIVED_DETERMINISTIC** (`[0,0,0]`) |
| `consecutive_all_ok_rounds` | MISSING (no field/rollup) | **DIRECT** (recovery field) |
| `timestamp`, `config_fingerprint` | SYNTHETIC | SYNTHETIC |
| `tcp_reachable`, `reality_dest_usable` | HEURISTIC | HEURISTIC |
| **status** | **PARTIAL** | **PARTIAL** |

The two rounds are almost complementary in what they *do* carry, yet **both fail
promotion** on the same universal core: `{timestamp, config_fingerprint,
tcp_reachable, reality_dest_usable}`. That four-field set is present in **every**
historical round and is structurally unfillable from committed historical evidence.
Therefore **no historical round can become a clean canonical candidate** under the
strict rule — exactly as the spike was meant to surface.

(Spot-checks consistent with this, not run as separate outputs: R60 = uniform
infra-dead → INCONCLUSIVE, same universal blockers; R77 = clean cohort-A all_ok but
no phase-probe → same phase-axis block as R91.)

---

## Do we need canonical schema v2?

**Not for structural reasons** — every projection that reaches `PARTIAL` does so on
*semantic* provenance, not on a shape the canonical schema cannot hold. The
canonical schema (`external_observation.schema.json`) is fine as-is for **native
live** observations, where `timestamp` is a real instant, `config_fingerprint` is a
real hash, the phase axes come from the live probe, and `tcp_reachable` /
`reality_dest_usable` are measured. The gap is specific to **historical** evidence.

So the decision is about *where historical evidence lives*, not about fixing the
canonical schema.

### Route 1 — keep canonical live schema strict; historical stays at the projection layer (permanent)

- Canonical `external_observation` remains a **live-only** corpus. Historical
  rounds are represented **only** as `historical-projection` records (this spike's
  envelope) and are **never** promoted.
- Pros: zero risk of historical-adapted evidence contaminating live observations or
  being miscounted as a parity increment (S4§E); no schema churn; the projection
  envelope already carries full provenance + blockers for audit.
- Cons: historical and live records have different shapes, so any cross-corpus query
  must understand both (the `live_rollup.json` already aggregates historical, so this
  is largely a non-issue).

### Route 2 — design a canonical schema v2 with explicit provenance

- Add explicit provenance/origin to the canonical schema (e.g. required
  `record_origin`, optional per-field provenance, allow `timestamp`/`config_fingerprint`
  sentinels) so historical-adapted records can be *first-class* canonical entries.
- Pros: one unified corpus + query path.
- Cons: substantial schema + validator churn; permanently weakens the meaning of a
  canonical record (a "canonical observation" could now be a synthesized historical
  projection); high risk of the exact conflation S4§E forbids. The universal blockers
  ({timestamp, config_fingerprint, tcp_reachable, reality_dest_usable}) would all
  become "allowed to be synthetic/absent", which guts the guarantees that make a live
  record trustworthy.

### Recommendation — **Route 1 (single recommended route).**

Keep the canonical live schema strict and let historical evidence live permanently
at the projection layer. It matches the project's standing discipline (do not coerce
unknown/mixed historical evidence into canonical booleans; do not invent exit codes;
historical ≠ live ≠ parity increment). A canonical **v2** is **not** recommended now;
if a unified query ever becomes a real need, prefer extending the *projection* layer
(or a read-only view over both corpora) over weakening the canonical contract.

Optional, additive, non-blocking (only if/when native live records start being
written): add one **optional** `record_origin` enum to the canonical schema
defaulting to `live`, purely so a future live corpus can never be confused with a
projection. This is a one-line additive change, not a v2, and is out of scope for
this spike.

---

## Status & stop

A4.2A delivers the read-only projection prototype + R82/R91 projections + this
report, and **stops at the proposal**. No productionized adapter, no CI wiring, no
public-network run, no canonical-schema edit, no A4.2B. `canonical_candidate` is
`null` for both targets; the blocking sets above are the minimal field sets that
would each have to gain an honest source before promotion could even be considered.
