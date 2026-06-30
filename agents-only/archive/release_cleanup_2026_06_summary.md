<!-- tier: C -->
# Release Cleanup 2026-06 Summary

Purpose: replace the raw `release-cleanup-2026-06/` folder with a compact release-prep history.

## Release Acceptance Batches

- `app/` acceptance removed dead app source, empty/permanently disabled placeholder tests,
  simulated validation/performance tests, stale ignored RC artifacts, and corrected the
  analyze patch registry to use real `sb_core` patch builders.
- Root file acceptance cleaned release/navigation/config files, updated stale fuzz exclusion, corrected README volatile-state wording, and documented the remaining `rsa` advisory exception for the optional Arti/Tor graph.
- `.github` acceptance confirmed the directory contains only the workflow-disablement README and no `.github/workflows/*` paths.
- `agents-only` acceptance cleaned entry/navigation/governance docs and kept current evidence/reference/memory working sets in place.
- `.e2e` acceptance cleaned runtime artifact/script hygiene: repo-root discovery, tracked `pids/` and `soak/` anchors, and portable cleanup selection.
- `.cargo` acceptance moved rustdoc warning denial to effective `[build].rustdocflags` and fixed exposed CLI rustdoc warnings.
- PX-ACCEPT-01 local drop-in rehearsal built the real debug app binary and passed the GUI 1.25.1 composite-fixture probe with one non-blocking warning.

## Runtime / Sidecar Notes

- Runtime-sidecar cleanup notes covered reload ordering, sidecar liveness, runtime exit policy, context cleanup, and reuse handoff.
- These were design/audit/proposal records for release hardening. They should not be used as direct implementation instructions without checking current code.

## REALITY Tier-3 Notes

- REALITY-T3 release-cleanup notes captured ClientHello fingerprint scoping, measurement hardening, and GREASE correlation summaries.
- Durable conclusion is carried in `reality_summary.md` and `active_context.md`; raw sanitized capture summaries were removed during archive compression.

## Governance Notes

- Governance cleanup reinforced the single-source rule: volatile state belongs in `active_context.md`; stable rules belong in `CLAUDE.md`, `AGENTS.md`, and `reference/`.
- The cleanup itself made no product behavior, dual-kernel BHV, REALITY closure, workflow automation, or packaging-completion claim.

## Verification Pattern Preserved

- Each accepted cleanup batch recorded local checks at the time: syntax/format/link/consistency/boundary gates as applicable.
- Those historical probe scripts and raw logs were removed. Re-run current commands for present-tense verification.
