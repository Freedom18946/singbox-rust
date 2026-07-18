<!-- tier: A -->
# REALITY External Healthy-Cohort Observation — Record Schema + Validator

Machine-readable record format and a read-only validator for the **external
healthy-cohort observation** tier of the REALITY acceptance model. This tier
records pre-release real-network observation rounds (the MT-REAL-02 public
fresh-cohort) in a structured, auditable form so verdicts can be emitted and
checked by tooling instead of by hand.

> Authoritative protocol: `labs/interop-lab/docs/dual_kernel_golden_spec.md`
> S4 → **External Healthy-Cohort Observation Protocol** (sections A–F). This
> directory only **structures** the rules already defined there; it invents no
> new thresholds and binds no fixed public-node identity.

## The three-tier model (where this fits)

1. **Local deterministic gate** — `make verify-reality-local`
   (`labs/interop-lab/reality_local_fixture/`). Offline, deterministic
   merge-precheck. Wired as the opt-in `REALITY_LOCAL` L18 capstone gate; not
   server-side automatically enforced, and CI remains disabled.
2. **External healthy-cohort observation** — **this directory's schema**.
   Pre-release real-network observation. **NOT a merge gate.** No single public
   node (e.g. the historical `fresh09`) is a mandatory closure identity; dead
   nodes are excluded and replaced with a recorded reason.
3. **ClientHello fingerprint parity** — Chrome-current local shape/order/JA4 is
   closed by the local canary; real-network camouflage remains open and is not
   closed by occasional external-cohort success.

## Files

| File | Role |
|------|------|
| `external_observation.schema.json` | JSON-Schema (draft-07) **structural** spec of a record |
| `validate_external_observation.py` | stdlib-only **read-only** validator (structure + cross-field semantics) |
| `fixtures/*.valid.json` | valid PASS / DEGRADED / INCONCLUSIVE examples |
| `fixtures/invalid.*.json` | one isolated rule violation each |

**Division of labour:** draft-07 cannot express the cross-field semantics
(verdict consistency, infra-dead exclusion, replacement recording, no silent
expansion, banked-depth). The `.py` validator is therefore **authoritative** for
those rules; the `.schema.json` documents the field shapes. The validator uses
the Python standard library only — **no `jsonschema` / pip dependency**.

## Usage

```bash
python3 labs/interop-lab/reality_external_observation/validate_external_observation.py <record.json>
```

Exit `0` on a valid record (prints `observation_id` / cohort / round / verdict /
healthy & excluded counts / banked); non-zero on any violation (prints, per
violation: JSON `path`, failed `rule`, `actual` value, and a `fix` hint). The
input file is never modified.

Validate all fixtures:

```bash
for f in labs/interop-lab/reality_external_observation/fixtures/*.json; do
  python3 labs/interop-lab/reality_external_observation/validate_external_observation.py "$f"; echo "exit=$?  $f"
done
```

## Verdict rules (extracted from golden_spec S4 §C/§D/§F — no invention)

- **PASS** — `run_all_ok` ∧ `run_same_failure==0` ∧ `run_divergence==0` ∧
  `matrix_status==0` ∧ `matrix_timeout==false` ∧ `healthy_node_count>0`. A
  **banked** PASS additionally requires `consecutive_all_ok_rounds >= 3`
  (MT-REAL-02 recovery closure depth = 3 consecutive all_ok rounds; golden_spec
  S4 §F). A single 3/3 round is "banked", not closure.
- **DEGRADED** — a *reproducible client* anomaly: `run_divergence>0`, or a node
  `included_in_client_verdict` with a failed phase. It must **not** be triggered
  solely by infrastructure-dead nodes.
- **INCONCLUSIVE** — too few healthy nodes / node death / uniform infra
  same-failure / matrix timeout / incomplete evidence. **Never banked.**

## Invariants the validator enforces (A4.0b)

Structural rules come from `external_observation.schema.json`; the cross-field
semantic rules below are enforced by the `.py` validator (golden_spec S4 §C/§D/§E):

1. `summary.healthy_node_count` == number of nodes with `infra_health == "healthy"`.
2. `summary.excluded_infra_dead_count` == number of `infrastructure-dead` nodes.
3. a node with `included_in_client_verdict == true` must be `healthy`.
4. a `PASS` round must include at least one node in the client verdict.
5. under `PASS`, every included node passes all four phases
   (`direct_reality`/`transport_reality`/`vless_dial`/`vless_probe_io`).
6. `summary.run_all_ok == true` requires >= 1 included node AND every included
   node's four phases all true.
7. a non-null `replacement_for` must reference an id in `run_plan.planned_node_ids`.
8. a node with `replacement_for` set must record a non-empty `replacement_reason`.
9. `run_plan.planned_node_ids` entries are unique.
10. `nodes[].node_id` values are unique.
11. `PASS` or `banked` requires `run_plan.subset_schema_gate_passed == true`.
12. `PASS` or `banked` requires `run_plan.violations == []`.
13. `PASS` or `banked` requires `run_plan.no_silent_expansion == true`.

Plus the standing rules: an infra-dead node must be excluded with a non-empty
`exclusion_reason` (node outage is not a Rust regression, S4 §B); every observed
node must be planned or a recorded replacement (no silent sample-face expansion,
S4 §E); a banked `PASS` needs `consecutive_all_ok_rounds >= 3` (S4 §F); an
`INCONCLUSIVE` round is never banked.

Fixtures cover all of the above — valid `PASS`/`DEGRADED`/`INCONCLUSIVE`, plus one
isolated violation each for: missing-required, bad-verdict,
infra-dead-counted-as-client-regression, inconclusive-banked, replacement-no-reason,
silent-expansion, pass-with-divergence, pass-with-matrix-timeout,
healthy-count-mismatch, pass-with-node-phase-failure, included-unknown-node,
replacement-for-unplanned-node, duplicate-node-id, pass-with-subset-gate-failed.

## Scope / non-goals

This is documentation + validation tooling only. It does **not** run public
nodes, does not modify the local fixture or any business source, is not wired
into CI or the L18 capstone, adds no GitHub workflow, and is not the
uTLS-fingerprint (tier-3) engineering.
