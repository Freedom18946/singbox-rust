<!-- tier: B -->
# A4.3 — Historical Projection-Layer Disposition (proposal)

Read-only governance card. Adjudicates the **final disposition of the REALITY
historical-projection layer** (the A4.2A prototype
`agents-only/archive/mt_real_02/a42_historical_projection_spike/`). Decision up front:

> **Recommended route: C — distill a stable projection *contract* / provenance
> convention now, and DEFER promoting any formal adapter/tool.** Unique
> recommendation; not a compromise. C *operationalizes* A4.2A's "Route 1" (canonical
> live schema stays strict; historical evidence is **terminal** at the projection
> layer) and adds exactly one durable artifact — a frozen provenance convention plus
> the mechanical proof — while explicitly refusing to ship a maintained tool the
> evidence does not yet justify.

This card **stops at the proposal**. It runs no public network, edits no business
source / canonical schema / validator / CI / registry, and leaves
`agents-only/a0_reality_spike/` untouched.

---

## A. Authoritative context read (in order)

`CLAUDE.md` · `agents-only/active_context.md` · `agents-only/memory/workflow_notes.md` ·
`agents-only/archive/mt_real_02/a41_historical_mapping_spike.md` ·
`agents-only/archive/mt_real_02/a42_historical_projection_spike/{README.md,report.md,historical_projection.schema.json,adapt_historical_round.py}`
· `labs/interop-lab/docs/dual_kernel_golden_spec.md` (S4 §A–§F) ·
`labs/interop-lab/reality_external_observation/README.md` (+ schema) · `git log -12`
(HEAD = `1c3c11f5`) · `git status` (only `a0_reality_spike/` untracked).

Standing constraints honored: canonical schema v1 stays STRICT (native-live only);
historical records never auto-promote; no unknown/mixed→canonical bool coercion; no
invented matrix exit code; no fresh09 identity binding; public cohort = pre-release
observation, never a merge gate.

## B. Corpus total & scan success

- `agents-only/mt_real_02_evidence/` holds **34** round summaries (`round*_summary.json`;
  `live_rollup.json` and `r76_..._plan.json` are not round summaries).
- The **unmodified** prototype (`adapt_historical_round.py`, sha256 `265434d2…`,
  re-verified byte-identical) projected **34/34 successfully, 0 failures, 0
  self-validation errors**, in two passes (default no-rollup = canonical; +rollup =
  sensitivity probe).
- Full machine artifact: `a42_historical_projection_spike/outputs/batch_inventory.json`.
- **No script breakage to classify** — the prototype is stable across the entire
  corpus, including the awkward eras (no-runs, label-only, matrix-status-object).

## C. Epoch coverage matrix

| Epoch | files | ok | status | rollup-dep field | mixed* | most-common blockers (per round) |
|---|---|---|---|---|---|---|
| R41_R42_NO_RUNS | 2 | 2 | UNSUPPORTED×2 | consec (no status change) | 0 | universal-4 + ~16 MISSING (20 blk) |
| R44_R73_RUN_LABELS | 17 | 17 | PARTIAL×17 | consec ×17 | 1→3 | universal-4 + 4 phase-axis(H) + matrix_status + gate + intake (17 blk) |
| R77_R81_PRE_GATE | 5 | 5 | PARTIAL×4, **UNSUPPORTED×1 (R81)** | consec ×5 | 1 | universal-4 + phase-axis(H) + matrix_status + consec (12 blk; R81=21) |
| R82_R84_SUBSET_GATE_PHASE_PROBE | 3 | 3 | PARTIAL×3 | consec ×1 (R82) | 0→1 | universal-4 + matrix_status (R83/R84=5 blk — corpus minimum) |
| R85_R88_RECOVERY | 4 | 4 | PARTIAL×4 | — | 0 | universal-4 + phase-axis(H) (8 blk); **MISSING family empty** |
| R89_R91_MATRIX_STATUS_OBJECT | 3 | 3 | PARTIAL×3 | — | 0 | universal-4 + phase-axis(H) (8 blk); **MISSING family empty** |

`*mixed` = prototype warning count → **true multi-mode count** (see §F.G3; prototype
under-fires). Per-epoch DIRECT / DERIVED_DETERMINISTIC / DERIVED_HEURISTIC /
SYNTHETIC / MISSING field families are enumerated per epoch in `batch_inventory.json`
(`epochs.*.prov_families`). Key shape: DIRECT/DD widen monotonically R41→R91; only the
phase-probe epoch (R80/82/83/84) puts the four phase axes in DIRECT; the late epochs
(R85+) reach an empty MISSING family. **rollup dependency touches exactly one field
(`summary.consecutive_all_ok_rounds`) and never flips a status.**

## D. promotion_status total distribution

| status | count |
|---|---|
| PROMOTABLE_CANDIDATE | **0** |
| PARTIAL | 31 |
| UNSUPPORTED | 3 (R41, R42, R81) |

`canonical_candidate = null` on **all 34**. No round is promotable — by design and by
structure (§F).

## E. Blocker frequency (global, top)

| blocker | rounds | class |
|---|---|---|
| `config_fingerprint` | 34 | MISSING ×19 / SYNTHETIC ×15 — **never real** |
| `timestamp` | 34 | SYNTHETIC ×34 (date→midnight) |
| `nodes[].tcp_reachable` | 34 | HEURISTIC ×34 (never separately observed) |
| `nodes[].reality_dest_usable` | 34 | HEURISTIC ×34 (never separately observed) |
| `nodes[].{direct,transport}_reality`, `vless_{dial,probe_io}` | 30 each | HEURISTIC (no phase probe); DIRECT on the other 4 |
| `summary.matrix_status` | 27 | MISSING (no per-run int); DD on 7 (R85+) |
| `summary.consecutive_all_ok_rounds` | 25 | MISSING (no recovery field, no rollup) |
| `run_plan.subset_schema_gate_passed` / `violations` | 24 | MISSING pre-R82 |
| `intake_counts.*` | 20 | MISSING pre-R77 |
| `run_plan.no_silent_expansion` | 19 | MISSING pre-R77 |

**Universal-four floor:** `{config_fingerprint, timestamp, tcp_reachable,
reality_dest_usable}` block **every** PARTIAL round; even the corpus-best rounds
(R83/R84, 5 blockers) carry all four. No round is within reach.

## F. Heuristic / synthetic / missing & risk summary

**Provenance discipline holds uniformly across all 34 (mechanical audit, all clean):**
0 promotable; `canonical_candidate` null ×34; **no** heuristic/synthetic field in any
candidate; **no** blocker-listing violation; phase axes DIRECT **only** on the real
phase-probe rounds R80/R82/R83/R84, DERIVED_HEURISTIC elsewhere (never DIRECT/DD from
a label heuristic); `summary.matrix_status` only MISSING or DERIVED_DETERMINISTIC
(real per-run ints) — **never invented**; pre-R44 + no-live R81 → UNSUPPORTED with no
per-node fabrication; the 2 bi-modal-warned rounds keep detail in `phase_class`/notes
(phase booleans not collapsed).

**Adversarially verified** (8-agent workflow, default agent type + schema per
`workflow_notes.md`; 0 nulls): every load-bearing claim **CONFIRMED**, none refuted.
Verification surfaced three refinements, each re-derived by a deterministic local scan:

- **V3 correction (UNSUPPORTED mechanism).** R41/R42 *do* carry `by_outbound` per-node
  aggregates; they reach UNSUPPORTED via the **epoch hard-code** (`detect_epoch` n≤42),
  *not* via data absence. Only **R81** is truly `no_per_node`. The "NO_RUNS" epoch label
  is a slight misnomer (R41/R42 lack a `runs[]` array + phase probe, not per-node data).
  Conclusion unchanged: no fabrication, `canonical_candidate=null`.
- **G3 — bi-modal disclosure under-fires.** The prototype's `mixed / bi-modal` warning
  fires only when `run_all_ok>0` coexists with a failure (2 files: R73, R78). The
  **true multi-mode set is 7 files** (R54, R56, R57, R59b, R73, R78, R83 — nodes
  mixing `run_divergence`+`run_same_failure` with no `all_ok`). `node_infra_health`
  returns `healthy` for a divergence-carrier (defensible per S4 §B — infra up,
  divergence is a client anomaly), but the **disclosure warning is absent** on 5 of 7.
  Not a today-violation (phase booleans stay HEURISTIC → no false promotion), but a
  **contract-hardening item**.
- **S4 §E conflation seed (raw corpus).** **15/34 rounds (R77–R91)** carry a top-level
  `bhv_52_56_unchanged[_at_round_time]` key, stapling the 52/56 parity number onto
  fresh-cohort rounds. The **projection layer strips it** (not a canonical field, never
  enters `field_provenance`/`canonical_candidate`) — so the projection is a *filter*,
  not a propagator; the risk lives in the raw data and any prose summary.

**Two maturity gaps** (the reasons a *tool* is premature; not discipline violations):

- **G1 — `--rollup` is a flag, not a computation.** `has_rollup=bool(args.rollup)`
  flips `consecutive_all_ok_rounds` MISSING→DERIVED_DETERMINISTIC on the flag alone,
  without ever reading the rollup (blast radius 19 files; never changes a status). A
  "DERIVED_DETERMINISTIC" claim with no backing computation is itself a provenance
  smell a maintained tool must close (actually parse the rollup, or keep MISSING).
- **G2 — `observation_id` value never emitted.** `synth_observation_id()` is dead
  code; only the provenance *tag* is emitted. `round_id` is **not unique** (3× "61");
  the de-facto key is `source.sha256` (unique ×34). (Note: `batch_inventory.json`'s
  `harness_recomputed_*` id fields are a harness-side recomputation, **not** the
  prototype's output — labeled as such to avoid misleading a maintainer.)

**Structural ceiling (decisive).** The only rounds with DIRECT per-node phase axes
(**R80/82/83/84**) and the only rounds with a real integer `matrix_status`
(**R85–R91**) are **temporally disjoint — intersection ∅**. No round ever carries both
the hard-won phase evidence *and* the matured summary fields. This ceiling is
independent of the universal-four floor and **cannot be adapted away** — it is a fact
about how evidence was collected over time.

## G. Prototype stability judgment

**Stable as a read-only projector; not yet mature as a maintained tool.** It processes
the full heterogeneous corpus (34/34, fail-closed self-validation, zero discipline
violations) and faithfully refuses every forbidden coercion. But G1/G2 (unbacked DD
claim; unemitted id) and G3 (incomplete bi-modal disclosure) are real corners a
maintained `labs/` tool would have to harden first. The *method/convention* is mature
enough to freeze; the *implementation* is not mature enough to promote.

## H. Route comparison

| | **A — agents-only archive only** | **B — promote to `labs/interop-lab` tool** | **C — freeze contract, defer tool** |
|---|---|---|---|
| Captures durable provenance convention | ✗ (prose only) | ✓ (but as code) | **✓ (as frozen contract + proof)** |
| Matches a *recurring* need today | n/a | ✗ none (0 promotable; `live_rollup` aggregates; tier is pre-release, not a gate) | n/a (defers tool until need exists) |
| Prototype maturity required | none | **fails: G1/G2/G3 must-fix** | none (documents gaps) |
| Discipline risk | human rot (G3 under-disclosure unwatched) | **highest — removes the structural firewall** | doc-decay (mitigated by committed proof) |
| Advocate self-rating | 4/5 | **3/5** | 4/5 |

**Why not A:** safe but under-delivers — it walks away from the newly-surfaced,
non-obvious lessons (G3 bi-modal disclosure rule; the 15-file `bhv_52_56` conflation
seed; the temporal-disjointness ceiling) instead of freezing them, leaving the whole
discipline in prose.

**Why not B (and why it is the single most dangerous route):** the canonical validator
has **no `record_origin` discriminator** and the canonical schema cannot carry one
(`required` omits it; `additionalProperties:false`). Today the *only* firewall keeping a
synthesized historical round out of the live corpus is that the projector emits a
**differently-shaped** envelope and leaves `canonical_candidate=null`. Co-locating a
tool beside the canonical validator makes "just fill in `canonical_candidate` and
validate it" the path of least resistance — and it would pass clean, because every
blocker the projector reports (synthetic timestamp, gitrev fingerprint, unobserved
tcp/reality) is invisible to the canonical validator. From there an S4 §E miscount as a
52/56 increment is one careless sentence away (the `bhv_52_56` seed is already in 15
files). B also fails its own fit conditions: no recurring need, and G1/G2/G3 say the
provenance rules are not yet tool-mature.

**Why C:** the projection *method* has proven, durable provenance-audit value, but
(i) 0 rounds are promotable and the ceiling is structural, (ii) there is no recurring
production need (pre-release observation, not a gate; `live_rollup` already
aggregates), and (iii) the implementation has three unhardened corners. C captures
100% of today's realizable value (freeze the convention + commit the mechanical proof)
at near-zero ongoing cost, keeps the canonical contract strict, and defers a formal
tool until a **native live** corpus actually makes rounds promotable and creates a real
maintenance payoff. C is A4.2A Route 1, made concrete and terminal.

## I. Recommended route — **C** (unique)

Adopt Route C. Concretely, the *next* card (not executed here) should author a short
frozen **projection contract** that pins, as terminal conventions:

1. the provenance vocabulary (DIRECT / DERIVED_DETERMINISTIC / DERIVED_HEURISTIC /
   SYNTHETIC_PLACEHOLDER / MISSING) and the **PROMOTABLE-iff-every-required-field-is-
   DIRECT/DD** rule;
2. the hard-prohibition list (no invented matrix code; no label→phase into a canonical
   bool; date→midnight stays SYNTHETIC; gitrev stays a proxy; pre-R44/no-live →
   UNSUPPORTED; **bi-modal disclosure must cover divergence+same_failure, fixing G3**);
3. the **universal-four floor** and the **temporal-disjointness ceiling** as the two
   structural proofs that historical evidence is permanently non-promotable;
4. the rule that the projection **strips** `bhv_52_56_*` and that a projection is
   **never** a live observation and **never** a 52/56 parity increment (S4 §E);
5. `source.sha256` (not `round_id`) as the join key; observation_id deferred with G2
   noted.

The formal contract is the deliverable of the next card; this card decides C and
specifies its content.

## J. Persist this report?

**Yes** — write this disposition record (originally top-level B-tier, now archived at
`agents-only/archive/mt_real_02/a43_projection_disposition.md`) and **persist
`a42_historical_projection_spike/outputs/batch_inventory.json`** as the
mechanical proof backstop (it answers the adversary's "doc-only loses the proof"
objection; reproducible from the unmodified prototype; self-discloses G3 + the
`bhv_52_56` seed). No other on-disk change.

## K. Recommended commit (do NOT auto-commit; excludes `a0_reality_spike/`)

Minimal staging (exactly two new agents-only files):

```
git add agents-only/archive/mt_real_02/a43_projection_disposition.md \
        agents-only/archive/mt_real_02/a42_historical_projection_spike/outputs/batch_inventory.json
```

Commit message:

```
docs(reality): adjudicate A4.3 projection-layer disposition (route C)

Full-corpus read-only inventory via the unmodified A4.2A projector: 34/34
rounds projected, 0 PROMOTABLE_CANDIDATE, canonical_candidate null. Provenance
discipline holds across all six epochs (adversarially verified, 0 refuted).
Surfaces a structural promotion ceiling (phase-probe R80/82/83/84 disjoint from
matrix-status R85+) and three hardening items (G1 rollup-flag, G2 unemitted
observation_id, G3 bi-modal under-disclosure). Recommends route C: freeze the
projection provenance contract, defer any formal tool; canonical schema stays
strict; historical evidence terminal at the projection layer.
```

## L. Gate results

- `git diff --check`: **clean** (no whitespace/conflict errors).
- `bash agents-only/06-scripts/check-boundaries.sh` (strict): **exit 0** — 537 V7
  assertions PASS, 0 violations. (NB: the CLAUDE.md/memory "exits 1" drift note is now
  **stale** — fixed by HEAD commits `2722d3ed`/`695ed13a`.)
- `cargo check --workspace --all-features`: **PASS** (0 errors, 0 warnings, ~1m56s).

## M. git status --short

Tracked tree clean apart from the two new allowed agents-only files;
`agents-only/a0_reality_spike/` remains untouched untracked. (Live output in the
session.)

## N. Next-card suggestion (do NOT execute here)

**A4.4 — author the frozen projection contract** specified in §I (a short A-tier
`reference/` doc), explicitly fixing G3's disclosure rule in the convention, and noting
G1/G2 as deferred implementation items that only matter if/when a tool is ever built.
Strictly documentation; no tool, no CI, no canonical-schema edit, no public network.
Separately, refresh the stale `boundary-gate-drift` memory note (gate now exits 0).
