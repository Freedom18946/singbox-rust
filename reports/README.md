# Reports Directory

This directory contains a mixed snapshot of tracked reports, historical audit documents, and generated runtime artifacts.

Do not treat `reports/` as the sole source of truth for project status. Current status and dual-kernel parity closure are maintained in:

- `labs/interop-lab/docs/dual_kernel_golden_spec.md`
- `agents-only/active_context.md`
- `agents-only/workpackage_latest.md`

## Layout

Top-level reports:

- `ACCEPTANCE_QC_2025-11-24.md`
- `GO_DIFF_ANALYSIS_2026-01-31.md`
- `L18_REPLACEMENT_CERTIFICATION.md`
- `L19_REALITY_ALIGNMENT.md`
- `L20_DEEP_ALIGNMENT.md`
- `L3_AUDIT_2026-02-10.md`
- `L3_AUDIT_2026-02-10_REMEDIATION.md`
- `L4_QUALITY_RECHECK_2026-02-10.md`
- `PERFORMANCE_REPORT.md`
- `PX015_LINUX_VALIDATION_2026-02-10.md`
- `TEST_COVERAGE.md`
- `VERIFICATION_RECORD.md`
- `capabilities.json`
- `feature_matrix_report.txt`
- Chinese audit notes: `第一轮审计意见.md`, `第二轮5.4pro审议意见.md`

Subdirectories:

- `benchmarks/` - tracked benchmark outputs and Criterion exports
- `l18/`, `l19/`, `l20/`, `l21/` - phase-specific evidence and artifacts
- `runtime/` - runtime capability probe outputs
- `security/` - security and interop artifacts referenced by security/TLS reports
- `stability/` - stability templates plus tracked run outputs
- `stress-tests/` - stress test logs and summaries

## Reading Guide

Use these files as historical evidence or supporting material, not automatic completion proof.

- `capabilities.json` is a capability ledger snapshot, not a substitute for behavior-level verification.
- `VERIFICATION_RECORD.md`, `PERFORMANCE_REPORT.md`, and `L18_REPLACEMENT_CERTIFICATION.md` contain historical material and must be read with their in-file warning banners.
- `feature_matrix_report.txt` is a feature/compile matrix snapshot. It is not the same thing as end-to-end or dual-kernel parity evidence.
- `security_audit.md` should be read together with `security/`.

## Artifact Policy

This tree currently mixes tracked documents and tracked generated outputs. In practice:

- phase reports and summary markdown/json files are retained for audit history
- bulky generated artifacts may still exist under `l18/`, `l21/artifacts/`, `benchmarks/criterion_data/`, `stability/`, and `stress-tests/`
- new documentation should not assume every generated artifact here is authoritative, complete, or reproducible from the current slim snapshot

If you add new material here:

- prefer concise summary reports over raw logs
- place phase-specific evidence under the matching phase directory
- keep general product documentation in `docs/`, not `reports/`
- avoid reintroducing GitHub Actions or workflow-based status claims; workflow automation is disabled in this repository

## See Also

- [Main README](/Users/bob/Desktop/Projects/ING/sing/singbox-rust/README.md)
- [Development Guide](/Users/bob/Desktop/Projects/ING/sing/singbox-rust/docs/04-development/README.md)
- [Dual-Kernel Golden Spec](/Users/bob/Desktop/Projects/ING/sing/singbox-rust/labs/interop-lab/docs/dual_kernel_golden_spec.md)
- [Active Context](/Users/bob/Desktop/Projects/ING/sing/singbox-rust/agents-only/active_context.md)
- [Phase Map](/Users/bob/Desktop/Projects/ING/sing/singbox-rust/agents-only/workpackage_latest.md)
- [Go Parity Matrix](/Users/bob/Desktop/Projects/ING/sing/singbox-rust/agents-only/reference/GO_PARITY_MATRIX.md)

---

**Last updated**: 2026-03-21
**Purpose**: report index, historical evidence map, and artifact-orientation notes
