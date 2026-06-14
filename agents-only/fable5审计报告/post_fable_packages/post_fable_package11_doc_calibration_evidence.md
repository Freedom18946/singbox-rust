<!-- tier: B -->
# post_fable_package11_doc_calibration_evidence

## Scope

Package11 closes CAL-26 by calibrating public and semi-public documentation. It
does not change product code, runtime behavior, config behavior, workflows, or
the original fable5 audit body.

## CAL-26 Disposition

| Drift area | Disposition |
|---|---|
| README maintenance wording | Replaced with active post-FABLE calibration wording and pointed live status to `agents-only/active_context.md`. |
| Ledger and GUI readiness ambiguity | README and `docs/STATUS.md` now state that scoped ledgers, BHV, REALITY/T3, and MT-GUI-04 style counts are not GUI-ready, drop-in-ready, or full behavior parity proof. |
| Capability ledger staleness | `docs/capabilities.md` now identifies itself as a docs-only historical snapshot. `reports/capabilities.json` has a `staleness` object that points readers to live status sources. |
| Historical test/cleanup docs | `docs/TEST_EXECUTION_SUMMARY.md` and `docs/CLEANUP_COMPLETION_REPORT.md` now have historical snapshot banners. |
| Historical migration/deployment docs | `docs/MIGRATION_GUIDE.md` and `docs/DEPLOYMENT_CHECKLIST.md` now have historical snapshot banners; their top-level readiness wording was softened. |

## Capability Generator Decision

Command:

```bash
python3 scripts/capabilities/generate.py --out /tmp/capabilities.package11.json
```

Result:

- PASS: generator wrote `/private/tmp/capabilities.package11.json`.
- Generated metadata: `source_commit=226581b7`, `profile=docs-only`,
  `capabilities=9`, `claims=0`.
- Not written back: generated output still contains stale static evidence anchor
  `tls.ech.quic -> crates/sb-config/src/validator/v2.rs:1`.

Decision: keep tracked capability entries unchanged and add staleness metadata
instead of presenting the generator output as a current refresh.

## Verification Results

```bash
rg -n "maintenance mode|Maintenance mode|209/209|55/55|GUI ready|drop-in|capabilities.json|TEST_EXECUTION_SUMMARY|CLEANUP_COMPLETION_REPORT" README.md docs reports agents-only/fable5审计报告/post_fable_packages
```

Result: PASS after review. Remaining matches are caveats, package notes,
historical `reports/` provenance, or bannered historical docs. The current FAQ's
old `209/209` assertion was rewritten as a warning that ledger closure is not GUI
readiness or full behavior parity proof.

```bash
rg -n "Status\*\*: Maintenance mode|Repository Mode\*\*: Maintenance|100% feature parity|Deployment Status:\*\*.*READY|GUI ready|drop-in ready|drop-in-ready|GUI-ready" README.md docs reports agents-only/fable5审计报告/post_fable_packages
```

Result: PASS. Remaining matches are negative/caveat wording only.

```bash
python3 -m json.tool reports/capabilities.json >/tmp/capabilities.json.check
```

Result: PASS.

```bash
git diff --check
```

Result: PASS.

## Residual Follow-Up

- Repair or replace the capabilities generator's static evidence map before using
  it as a tracked refresh path.
