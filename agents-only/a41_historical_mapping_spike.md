<!-- tier: B -->
# A4.1 — Historical-Record Mapping Spike (final report)

Read-only spike. Maps the existing MT-REAL-02 historical round-summary corpus
(`agents-only/mt_real_02_evidence/*.json` + `live_rollup.json`) onto the canonical
`external_observation` schema v1
(`labs/interop-lab/reality_external_observation/`). Establishes what an eventual
adapter would face. A4.2A builds the read-only projection prototype on top of this.

## Method & confidence

- First-hand reads: `pass.valid.json`, R50/R60/R77/R81/R91 round summaries,
  `live_rollup.json`, the schema, and `validate_external_observation.py`.
- A fan-out workflow was run; its **adversarial-verify layer failed** (10 workers
  used `agentType:"Explore"` + a forced `schema`, which is unreliable — see
  `agents-only/workflow_notes.md`). The synthesizer (default agent type) produced a
  usable draft. **All load-bearing claims below were re-verified by a deterministic
  local Python scan**, which corrected several epoch-boundary errors in the draft
  and found a DIRECT phase-probe source the draft missed.

## 1. Verdict

1. **An adapter is required.** Historical summaries and canonical v1 are
   non-isomorphic in 4 hard ways (below); naive mapping fails the validator.
2. **Three collisions:** `summary.run_all_ok` (historical = integer COUNT / schema =
   BOOL); `matrix_status` (historical top-level = OBJECT, only R89–R91 / schema =
   INT); the four per-node phase booleans (schema = per-node single bool / historical
   main corpus = per-(outbound×run) label aggregates).
3. **Era heterogeneity:** fields arrive over four boundaries (below); early rounds
   are missing most provenance fields — adapter must branch and emit honest
   placeholders, never fabricate.
4. **Key correction (deterministic):** the four phase axes DO exist as DIRECT
   per-run structured data (`{ok,class}`) in **R80/R82/R83/R84** via
   `phase_probe_supporting_evidence.per_run[]`. Elsewhere they are only
   heuristically derivable from labels.

## 2. Real epoch boundaries (deterministically verified)

| feature / field family | earliest round | note |
|---|---|---|
| top-level `runs[]` (per-run `outbound`+`labels`) | **R44** | only R41/R42 lack it |
| `pre_gate` / `pre_gate.intake_counts` / `live_scope` / `live_scope.cohort` / `summary.run_health_counts` / `summary.run_all_ok`(int) | **R77** | NOT R81/R85 |
| `pre_gate.subset_schema_gate{passed,violations}` (recorded live) | **R82** | R81 was a no-live tooling round; gate first recorded at R82 |
| `head_at_gate` / `live_scope.auto_extended` | **R77** | R77–R91 (15 rounds) |
| recovery/banking (`recovery_consecutive_rounds_*`) | **R85** | — |
| `matrix_status` **object** (top-level) | **R89–R91 only** | but per-run int `matrix_status` exists R85+ (R91 runs = `[0,0,0]`) |
| phase-probe four axes (DIRECT) | **R80/R82/R83/R84** | `phase_probe_supporting_evidence.per_run[].<axis>.{ok,class}` |

Projection epochs used by A4.2A: `R41_R42_NO_RUNS`, `R44_R73_RUN_LABELS`,
`R77_R81_PRE_GATE`, `R82_R84_SUBSET_GATE_PHASE_PROBE`, `R85_R88_RECOVERY`,
`R89_R91_MATRIX_STATUS_OBJECT`.

## 3. Field-by-field map (D=DIRECT, d=DERIVED, M=MISSING, C=CONSTANT)

### Top-level
| field | class | source / rule | note |
|---|---|---|---|
| `schema_version` | C | `1` | validator-forced |
| `round_id` | D | `round` (incl. `"59-B"`) | 4 files share `"61"` → not unique; pair with observation_id |
| `timestamp` | d | `date`→`{date}T00:00:00Z` | **lossy**: no time-of-day; same-day rounds collide |
| `observation_id` | d→synth | `f"obs-…r{round}-{date}"` | no native id |
| `cohort_id` | d | `live_scope.cohort` (R77+ DIRECT) → else S4§F bucket / `classification.sub_branch` | identity binding retired (S4§E) |
| `config_fingerprint` | **M** | no content hash; proxy `pre_gate.head_at_gate` (R77+); intake hashes in `mt_mixed_fresh_evidence/reality_intake.json` (not per-round) | must placeholder + mark origin |
| `verdict` | d | run-health + infra-dead + matrix signals | DEGRADED "cross-round" qualifier not single-round decidable |
| `notes` | d | `description`+`interpretation[]`+annotations | only audit channel for lossy decisions |

### run_plan
| field | class | source | era |
|---|---|---|---|
| `subset_schema_gate_passed` | D | `pre_gate.subset_schema_gate_passed` | **R82+**; pre-R82 = honest `false`+violation note |
| `violations` | D | `pre_gate.subset_schema_gate.violations` | **R82+** |
| `planned_node_ids` | D | `pre_gate.dry_run.selected` / `live_scope.outbounds` | R77+; else back-fill from `by_outbound` (vacuous) |
| `no_silent_expansion` | d | `live_scope.auto_extended==false ∧ observed⊆planned` | **R77+** real; earlier vacuous |

### intake_counts — all **D** from `pre_gate.intake_counts.*`, era **R77+**; pre-R77 → 0 + "not observed".

### nodes[]
| field | class | source / rule | note |
|---|---|---|---|
| `node_id` | D | `by_outbound.<k>` / `runs[].outbound` | R73+ neutral `freshNN`; earlier region tags |
| 4 phase axes | **D** (R80/82/83/84) / **d** else | `phase_probe_supporting_evidence.per_run[].<axis>.ok`; else label→phase heuristic | **core lossy point**; bi-modal nodes uncollapsible to one bool |
| `infra_health` | d | S4§B uniform same-class (`probe_io class==reality class`)→dead; `run_all_ok>0`→healthy; matrix_error/timeout→unknown | drives 3 fields below |
| `phase_class` | d | dominant label / `same_failure_class` | free string; authoritative per-node descriptor |
| `exclusion_reason` | d | synth from class for infra-dead/unknown | validator: non-empty required for infra-dead |
| `included_in_client_verdict` | d | infra-dead→false else true | satisfies validator invariant |
| `credential_present`/`config_parse_ok` | d | ran→true (S4§A); `config_parse_ok=false` only R80 matrix_error | **tautology** for adapted data |
| `tcp_reachable`/`reality_dest_usable` | d (**low**) | inferred from failure class only | **not separately observed** |
| `replacement_for`/`replacement_reason` | **M** | prose rotation only; no per-node binding | default `null/null` (validator-safe) |

### summary
| field | class | source / rule | note |
|---|---|---|---|
| `run_all_ok`(bool) | d | `=(div==0 ∧ same==0 ∧ unknown==0 ∧ all_ok_count>0)` | ⚠️ **name/type collision** w/ historical int count |
| `run_same_failure`/`run_divergence`(int) | D | `run_health_counts.*` (R77+) | run counts, not per-occurrence label counts |
| `matrix_status`(int) | d | reduce per-run int (R85+, e.g. `[0,0,0]`→0) | ⚠️ historical top-level OBJECT (R89–R91); **don't invent** an int from buckets |
| `matrix_timeout`(bool) | d | `status_counts.matrix_timeout>0 ∨ object.matrix_timeout_runs>0` | — |
| `healthy_node_count`/`excluded_infra_dead_count` | d | recompute from emitted nodes[] | validator hard-checks the excluded count |
| `banked`(bool) | d | `=PASS ∧ closure flag ∧ consecutive>=3` | R85+; INCONCLUSIVE/DEGRADED → false |
| `consecutive_all_ok_rounds` | d | R85+ recovery field; else needs `live_rollup.json`; else 0 | single round pre-R85 has no chain depth |
| `source_threshold_note` | C | fixed S4§F citation | don't invent thresholds |

## 4. Schema traps (unreasonable / footgun fields)

1. **`summary.run_all_ok`** — name+type collision (int count vs bool). *Severity: high.* Add a one-line schema description.
2. **`summary.matrix_status`** — historical object (R89–R91) vs schema int. *Medium.* Describe as int exit status; object must be reduced.
3. **`nodes[].{4 phase axes}`** — per-node single bool vs per-run label corpus; bi-modal nodes inexpressible. *High.* Keep bool for native probes; for adapted data treat `phase_class`+notes as authoritative. (R80/82/83/84 are the DIRECT exception.)
4. **`nodes[].tcp_reachable` / `reality_dest_usable`** — not separately observable. *Medium.* Document best-effort.
5. **`nodes[].{credential_present,config_parse_ok}`** — tautological for adapted data. *Low.*
6. **`run_plan.subset_schema_gate_passed` / `no_silent_expansion`** — concept absent pre-R82/R77. *Medium.* Honest placeholders, not fabricated `true`.
7. **`summary.banked` / `consecutive_all_ok_rounds`** — multi-round properties in a single-round record; schema can't distinguish bank vs closure. *Medium.*
8. **`config_fingerprint`** — required non-empty, but no historical content hash. *Low.* Placeholder + origin marker.

## 5. Open questions (need a human decision before any adapter is productionized)

1. `consecutive_all_ok_rounds` for pre-R85: require `live_rollup.json`, or always 0+banked=false when absent?
2. label→phase heuristic acceptable, or prefer "all-true/all-false per node, detail in phase_class"? (R80/82/83/84 unaffected — DIRECT.)
3. `cohort_id`: S4§F bucket rule canonical, or prefer prose `kind`/`classification.sub_branch` when they disagree?
4. `observation_id` uniqueness: file-path-hash / sequence suffix acceptable (round+date not unique)?
5. add an optional `record_origin` discriminator to the canonical schema, or keep the marker only in notes/projection layer?
6. pre-R44 rounds (R41/R42): refuse per-node phase bools (→ unknown / INCONCLUSIVE) or skip entirely? **(A4.2A: UNSUPPORTED.)**
7. `matrix_status` exit codes 1 vs 124 are invented — in tension with "do not invent". **(A4.2A: do not invent; mark MISSING.)**

## 6. Final verdict (this round)

- An adapter is required, but historical → canonical is **not** a clean lift: a small
  universal set (`timestamp`, `config_fingerprint`, `nodes[].tcp_reachable`,
  `nodes[].reality_dest_usable`) is **unfillable** from committed historical evidence
  on every round, so **no historical round can be promoted to a clean canonical
  record**.
- The correct shape is a **projection layer** (provenance-annotated, non-canonical)
  that makes the fabrication boundary explicit and never coerces unknown/mixed
  evidence into canonical booleans or invents matrix exit codes.
- Implemented as the A4.2A read-only prototype:
  `agents-only/a42_historical_projection_spike/` (R82 and R91 both project to
  `PARTIAL`, `canonical_candidate=null`).
- Recommended route: **keep the canonical live schema strict; historical evidence
  lives permanently at the projection layer.** No canonical v2 now. (See A4.2A
  `report.md`.)
