<!-- tier: B -->
# A4.2A — Historical → External-Observation Projection (read-only spike)

A **read-only prototype**, not a production adapter. It projects ONE MT-REAL-02
historical round-summary JSON onto a **provenance-annotated, non-canonical
envelope** so we can answer one question precisely:

> *Given the real historical evidence, which canonical `external_observation`
> fields could a future promoter legitimately fill — and which would it have to
> fabricate?*

This spike deliberately **stops at the proposal**. It does **not** implement a
general "auto-promote historical rounds to canonical external observations"
adapter, is **not** wired into CI, **never** contacts the network, and **never**
mutates its inputs. It is an `agents-only/` spike and is intentionally kept out of
the formal tool dir `labs/interop-lab/reality_external_observation/` (which this
spike does not touch).

## Why a projection layer (not a direct adapter)

A4.1 established that historical round summaries and the canonical
`external_observation` schema are structurally non-isomorphic, and that **some
required canonical fields have no honest historical source** (synthesized
timestamp, no config-content fingerprint, per-node `tcp_reachable` /
`reality_dest_usable` never observed). Coercing those into canonical values would
fabricate evidence. The projection layer makes the fabrication boundary explicit:
every canonical field is tagged with its provenance, and a record only becomes a
(still-unpromoted) `canonical_candidate` when **every** required field is `DIRECT`
or strictly `DERIVED_DETERMINISTIC`.

## Files

| File | Role |
|------|------|
| `historical_projection.schema.json` | draft-07 structural spec of the projection envelope (NOT the canonical schema) |
| `adapt_historical_round.py` | stdlib-only, read-only projector + built-in self-validation against the schema |
| `outputs/r82.projection.json` | projection of R82 (subset-gate + DIRECT phase-probe era) |
| `outputs/r91.projection.json` | projection of R91 (recovery/closure + matrix_status-object era) |
| `report.md` | findings: per-field provenance tables, promotion blockers, route analysis, recommendation |

## Usage

```bash
python3 agents-only/archive/mt_real_02/a42_historical_projection_spike/adapt_historical_round.py \
    agents-only/mt_real_02_evidence/round82_fresh04_recheck_summary.json \
    [--rollup agents-only/mt_real_02_evidence/live_rollup.json] \
    [--out agents-only/archive/mt_real_02/a42_historical_projection_spike/outputs/r82.projection.json]
```

- Input is read-only; output goes to stdout (or `--out`).
- `--rollup` only matters for reconstructing `consecutive_all_ok_rounds` on a
  pre-R85 round that lacks an embedded recovery field; without it that field is
  marked `MISSING` (never guessed).
- The script **self-validates** its output against `historical_projection.schema.json`
  before emitting; on any structural violation it prints diagnostics and exits 2
  without writing.

## Provenance vocabulary

| Tag | Meaning | Eligible for `canonical_candidate`? |
|-----|---------|-------------------------------------|
| `DIRECT` | copied from an existing source field of compatible type+meaning | yes |
| `DERIVED_DETERMINISTIC` | computed by a fixed rule from present fields (no judgement) | yes |
| `DERIVED_HEURISTIC` | inferred by a lossy/ambiguous heuristic (e.g. label→phase) | **no** |
| `SYNTHETIC_PLACEHOLDER` | fabricated (synthesized timestamp, gitrev-proxy fingerprint) | **no** |
| `MISSING` | no usable historical source | **no** |

## Hard prohibitions (enforced by the projector)

It never: writes an unknown phase as `false`; flattens a bi-modal phase to a
stable boolean; puts a label→phase heuristic into a canonical phase boolean;
invents a `matrix_status` exit code; passes a midnight-from-date off as a real
timestamp; passes a git HEAD off as a real config fingerprint; reports a pre-R82
(absent) subset gate as a real pass; fabricates per-node data for a pre-R44 round;
describes a projection as a dual-kernel parity increment; or restores any
fixed-node identity binding (e.g. fresh09).

## Scope / non-goals

Documentation + read-only tooling only. Not a merge gate, not CI-wired, not a
canonical record producer. The canonical live schema + validator under
`labs/interop-lab/reality_external_observation/` are unchanged.
