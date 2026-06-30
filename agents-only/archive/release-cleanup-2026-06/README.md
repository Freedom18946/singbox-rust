<!-- tier: C -->
# Release-Cleanup 2026-06 Archive Summary

Purpose: shrink top-level `agents-only/` navigation before release while keeping raw
evidence available under archive.

## What Moved

### Release Acceptance

Location: `release-acceptance/`

- Root, `.github`/`agents-only`, `.e2e`, `.cargo`, and PX drop-in rehearsal acceptance
  reports.
- PX rehearsal probe script moved with its report so runnable historical evidence remains
  grouped.
- These records are historical release-hygiene evidence, not product behavior claims and
  not dual-kernel parity movement.

### Runtime / Sidecar

Location: `runtime-sidecar/`

- App reload cleanup and V2Ray sidecar reload-order tracks.
- App sidecar bind/liveness/runtime-exit tracks.
- App V2Ray surface/simple compatibility tracks.
- Service bind-failure propagation audits/checkpoints.
- These tracks are closed or deferred as recorded in their own files. They remain useful
  for audit, but no longer belong in the live navigation root.

### REALITY Tier-3

Location: `reality-tier3/`

- A2 local-gate wiring/capstone notes.
- T3 ClientHello capture, measurement hardening, parity harness, coordinated GREASE, and
  governance update artifacts.
- This keeps the boxed REALITY local-mainline evidence together. Current REALITY state is
  still owned by `agents-only/active_context.md` and the golden spec.

### Governance

Location: `governance/`

- Post-REALITY prioritization report. It is retained as historical decision input after
  later cleanup/acceptance rounds superseded its immediate recommendations.

## What Stayed Top-Level

- S-tier entry files: `active_context.md`, `workpackage_latest.md`, `init.md`.
- Live/historical working sets still directly referenced by current docs or tooling:
  `mt_real_02_baseline.md`, `mt_real_02_evidence/`, fresh intake files, `post1313/`,
  `reference/`, `memory/`, `06-scripts/`, `templates/`.
- Historical projection spike files stayed top-level because
  `reference/reality_historical_projection_contract.md` still points there as the
  retained prototype/contract evidence.

## Local Artifact Cleanup

Removed ignored local-only artifacts under `agents-only/`:

- Python `__pycache__/` directories.
- `*.log` runtime/build logs.
- `*.pid` runtime pid files.

Kept ignored but still-referenced REALITY local configs and snapshots, including
`agents-only/mt_real_01_evidence/phase3_ip_direct.json`, because MT-REAL-02 tooling and
historical reports still point at them.

## Non-Claims

- No source behavior changed.
- No GitHub workflow automation was added or restored.
- No REALITY closure, public-cohort result, or dual-kernel BHV/parity movement is claimed.
- This is navigation and local-artifact hygiene only.
