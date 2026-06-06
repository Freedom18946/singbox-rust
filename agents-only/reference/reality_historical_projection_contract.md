<!-- tier: A -->
# REALITY Historical-Projection Contract

> **A-tier stable reference.** Freezes the provenance discipline that governs the
> REALITY *historical-projection layer* — the read-only mapping of MT-REAL-02
> historical round summaries onto the canonical external-observation field set.
> Distilled from the A4.1–A4.3 spikes (read-only, adversarially verified) and adopted
> as **Route C** in `agents-only/a43_projection_disposition.md`.
>
> This document is a **contract, not a tool**. It does not ship, run, or wire any
> adapter. The prototype it describes stays in `agents-only/`; the canonical schema and
> validator under `labs/interop-lab/reality_external_observation/` are unchanged.
>
> **Authoritative sources** (this doc points, it does not copy volatile state):
> behavior/acceptance protocol = `labs/interop-lab/docs/dual_kernel_golden_spec.md`
> S4 §A–§F; canonical record contract =
> `labs/interop-lab/reality_external_observation/{external_observation.schema.json,
> validate_external_observation.py}`; the prototype + machine evidence =
> `agents-only/a42_historical_projection_spike/` (`adapt_historical_round.py`,
> `outputs/batch_inventory.json`); the disposition decision + full inventory =
> `agents-only/a43_projection_disposition.md`; volatile parity/phase state =
> `agents-only/active_context.md`.

---

## A. Scope

1. The canonical **external-observation schema v1**
   (`reality_external_observation/external_observation.schema.json`) serves **native
   live observation only** — records where `timestamp` is a real capture instant,
   `config_fingerprint` is a real config-content hash, the four phase axes come from a
   live probe, and `tcp_reachable` / `reality_dest_usable` are measured.
2. The **historical projection** is an **archive / provenance-audit layer**. Its job is
   to map a frozen historical round summary onto the canonical field paths while making
   every fabrication boundary explicit (per-field provenance + blocker list).
3. A historical projection is **never a live observation**.
4. A historical projection is **never a `52/56` dual-kernel BHV parity increment**
   (golden_spec S4 §E). Parity axes and their numbers live only in their own
   authoritative sources.
5. A historical projection **never auto-promotes** to a canonical record (see C).
6. **No fixed public-node identity** (e.g. the historical `fresh09`, or the original
   cohort-C `fresh01+fresh09+fresh15` binding) may be restored as a closure
   obligation. Public-cohort observation is pre-release and non-gating (S4 §E);
   `make verify-reality-local` (the local deterministic fixture) is the only
   merge-precheck.

## B. Provenance vocabulary (frozen)

Every canonical field path a projection touches is tagged with exactly one class:

| Tag | Definition | Allowed use |
|-----|------------|-------------|
| `DIRECT` | copied from an existing source field of compatible type **and** meaning | promotion-eligible |
| `DERIVED_DETERMINISTIC` | computed by a fixed rule from fields actually present, no judgement, no guessing | promotion-eligible |
| `DERIVED_HEURISTIC` | inferred by a lossy / ambiguous rule (e.g. run-label → phase) | **disclosure only; never promotion-eligible** |
| `SYNTHETIC_PLACEHOLDER` | fabricated to satisfy a required shape (date→midnight timestamp; gitrev-proxy fingerprint) | **disclosure only; never promotion-eligible** |
| `MISSING` | no usable historical source exists | **disclosure only; never promotion-eligible** |

The three non-eligible classes are **blockers**: any required canonical field carrying
one forces `PARTIAL` (or `UNSUPPORTED`). Every blocking field MUST appear in the
projection's `promotion_blockers` list.

## C. Promotion rule (frozen)

A projection is `PROMOTABLE_CANDIDATE` **iff all** of:

- every canonical **required** field has provenance ∈ {`DIRECT`, `DERIVED_DETERMINISTIC`};
- **no** field is `DERIVED_HEURISTIC`;
- **no** field is `SYNTHETIC_PLACEHOLDER`;
- **no** field is `MISSING`;
- the assembled `canonical_candidate` would pass the **live** validator
  (`validate_external_observation.py`) unmodified.

Even a `PROMOTABLE_CANDIDATE` is **only a candidate**:

- promotion requires an **explicit human promotion gate** — never automatic;
- a candidate is **never** written into the live observation corpus by the projection
  layer;
- `PARTIAL` and `UNSUPPORTED` projections carry `canonical_candidate = null`.

**Status of the frozen corpus:** across the entire MT-REAL-02 historical corpus
(R41–R91) **0 rounds are `PROMOTABLE_CANDIDATE`** (31 `PARTIAL`, 3 `UNSUPPORTED`); see
F for why this is structural, not incidental.

## D. Hard prohibitions (frozen)

A projection (or any future promoter/tool) MUST NOT:

1. write an unknown phase as `false`;
2. flatten a mixed / bi-modal phase into a single canonical boolean;
3. put a run-label → phase **heuristic** result into a canonical phase boolean;
4. invent a `matrix_status` exit code (e.g. `1` / `124`) when none was recorded;
5. pass a date-synthesized midnight off as a real capture timestamp;
6. pass a git-revision proxy off as a real config-content fingerprint;
7. report a pre-R82 (absent) subset-schema gate as a real pass;
8. fabricate a pre-R44 round into a per-node live observation;
9. propagate a `bhv_52_56_*` field as a parity increment (the projection **strips** it
   — it is not a canonical field; 15/34 raw rounds carry such a key, R77–R91);
10. write any projection into the canonical live observation corpus;
11. restore a fixed public-node identity as a closure obligation;
12. weaken the canonical validator (e.g. relax a required field, add a synthetic
    sentinel) for the sake of historical compatibility.

## E. Multi-mode disclosure rule (G3, frozen)

- "mixed / bi-modal" is **not** limited to `run_all_ok` coexisting with a failure. A
  node mixing `run_divergence` with `run_same_failure` (no `all_ok`) is **also**
  multi-mode and MUST be disclosed.
- Disclosure is written to `warnings` / `notes` / `phase_class` — the per-node single
  verdict must never silently absorb the mix.
- A **missing disclosure must never change `projection_status` to promotable**. (Today
  the per-node phase booleans on these rounds are already `DERIVED_HEURISTIC`, so an
  under-disclosure cannot cause a false promotion — but the disclosure is still owed.)
- A future formal tool **must fix G3** so the disclosure covers the full real
  multi-mode set recorded in `a43_projection_disposition.md` / `batch_inventory.json`
  (`bimodal_disclosure_audit`): the prototype warns on 2 rounds; the true multi-mode
  set is 7 (R54, R56, R57, R59b, R73, R78, R83).
- The current prototype's G3 under-disclosure is a **known, registered, un-hardened
  item** (see G); it must not be silently forgotten.

## F. Structural proofs (frozen; verified over the full corpus)

Two independent, mechanically-verified reasons no historical round can be cleanly
promoted (evidence: `batch_inventory.json`, unmodified prototype sha256 `265434d2…`):

1. **Universal-four floor.** Four canonical **required** fields are non-`DIRECT` /
   non-`DERIVED_DETERMINISTIC` on **every one of the 34** historical rounds:
   - `config_fingerprint` — `MISSING` ×19 (pre-R77, no `head_at_gate`) /
     `SYNTHETIC_PLACEHOLDER` ×15 (gitrev proxy); **never a real content hash**;
   - `timestamp` — `SYNTHETIC_PLACEHOLDER` ×34 (date→midnight; no time-of-day recorded);
   - `nodes[].tcp_reachable` — `DERIVED_HEURISTIC` ×34 (never separately observed);
   - `nodes[].reality_dest_usable` — `DERIVED_HEURISTIC` ×34 (never separately observed).
   These block promotion on every round regardless of epoch.

2. **Temporal-disjoint ceiling.** The two scarce evidence families never co-occur:
   - `DIRECT` per-node phase axes appear **only** in **R80 / R82 / R83 / R84** (the
     phase-probe rounds);
   - a real integer `summary.matrix_status` appears **only** in **R85–R91**;
   - their intersection is **∅** — no round carries both the hard-won per-node phase
     evidence and the matured per-run matrix status.
   This is a property of how evidence was collected over time; an adapter **cannot**
   close it. Combined with the universal-four floor, it is the structural guarantee
   that the projection layer is **terminal** for historical evidence, not a staging
   area.

## G. Deferred tool-hardening items (registered, NOT implemented here)

These are pre-conditions for any future promotion of the prototype to a formal tool.
They are recorded so they are not forgotten; this contract does not implement them.

- **G1 — `--rollup` must compute, not assert.** The prototype flips
  `summary.consecutive_all_ok_rounds` from `MISSING` to `DERIVED_DETERMINISTIC` on the
  presence of the `--rollup` flag alone, without ever reading the rollup (blast radius
  19 rounds; never changes a status). A real tool must actually parse
  `live_rollup.json` and recompute the chain depth, or keep the field `MISSING` with a
  note. A `DERIVED_DETERMINISTIC` claim without a backing computation is itself a
  provenance smell.
- **G2 — `observation_id` must be real and stably unique.** `synth_observation_id()` is
  dead code; the prototype emits only the field's provenance *tag*, never a value.
  `round_id` is **not unique** (3 rounds share `"61"`); the reliable join key today is
  **`source.sha256`** (unique across all 34). A real tool must generate and emit a
  stable unique id and add it to the projection envelope.
- **G3 — multi-mode disclosure coverage is incomplete.** See E.
- **Gate for promotion:** before any promotion to a formal tool, fix G1/G2/G3, then
  re-run the full historical corpus inventory **and** the adversarial verification
  (per A4.3) and re-confirm 0 discipline violations.

## H. Disposition (frozen)

- **Route C adopted** (`a43_projection_disposition.md`): freeze this contract; defer any
  formal tool.
- The projection **prototype remains in `agents-only/a42_historical_projection_spike/`**
  (B-tier spike). It is **not** moved to `labs/interop-lab/`.
- **No new formal adapter** is added now (no A4.2B, no CI wiring, no canonical-schema
  edit).
- If a **recurring** archive-audit need later emerges, re-evaluate tool promotion —
  subject to the G1/G2/G3 gate above and to the S4 §E firewall (a tool beside the
  canonical validator must not become a path for historical evidence to masquerade as
  a live observation).
- If a **unified query** over historical + live records is ever needed, prefer a
  **read-only view** over both corpora; **never** weaken the canonical schema to absorb
  historical projections.
