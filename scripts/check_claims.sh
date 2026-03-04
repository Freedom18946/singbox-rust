#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPORT_PATH="${ROOT}/reports/capabilities.json"

if [[ ! -f "${REPORT_PATH}" ]]; then
  echo "[claim-guard] missing report: reports/capabilities.json"
  exit 11
fi

python3 - "${ROOT}" "${REPORT_PATH}" <<'PY'
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
report_path = Path(sys.argv[2])

doc_files = [
    "README.md",
    "docs/capabilities.md",
    "docs/STATUS.md",
    "docs/RUST_ENHANCEMENTS.md",
    "docs/07-reference/platform-io.md",
    "agents-only/01-spec/01-REQUIREMENTS-ANALYSIS.md",
    "agents-only/02-reference/GO_PARITY_MATRIX.md",
]

high_risk_patterns = [
    re.compile(r"production ready", re.IGNORECASE),
    re.compile(r"full support", re.IGNORECASE),
    re.compile(r"27\+\s*fingerprints?", re.IGNORECASE),
    re.compile(r"(?:\bECH\b.*\bComplete\b|\bComplete\b.*\bECH\b)", re.IGNORECASE),
    re.compile(r"TUN,\s*Redirect,\s*TProxy.*✅", re.IGNORECASE),
]

medium_risk_patterns = [
    re.compile(r"209/209", re.IGNORECASE),
    re.compile(r"100%\s*parity", re.IGNORECASE),
    re.compile(r"feature parity", re.IGNORECASE),
    re.compile(r"100%\s*protocol coverage", re.IGNORECASE),
]


def classify_risk(text: str) -> str | None:
    for pattern in high_risk_patterns:
        if pattern.search(text):
            return "high"
    for pattern in medium_risk_patterns:
        if pattern.search(text):
            return "medium"
    return None


def scan_claims() -> list[dict[str, object]]:
    out: list[dict[str, object]] = []
    for rel in doc_files:
        path = root / rel
        if not path.exists():
            continue
        for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            text = raw.strip()
            if not text:
                continue
            risk = classify_risk(text)
            if risk is None:
                continue
            out.append(
                {
                    "source_path": rel,
                    "line": line_no,
                    "text": text,
                    "risk_level": risk,
                }
            )
    return out


def key_of(claim: dict[str, object]) -> tuple[str, int, str]:
    return (str(claim["source_path"]), int(claim["line"]), str(claim["text"]))


report = json.loads(report_path.read_text(encoding="utf-8"))
capabilities = {
    cap["id"]: cap for cap in report.get("capabilities", []) if isinstance(cap, dict) and "id" in cap
}
report_claims = {
    key_of(claim): claim
    for claim in report.get("claims", [])
    if isinstance(claim, dict)
    and "source_path" in claim
    and "line" in claim
    and "text" in claim
}

scanned_claims = scan_claims()

unmapped_errors: list[str] = []
high_risk_errors: list[str] = []

for claim in scanned_claims:
    k = key_of(claim)
    report_claim = report_claims.get(k)
    if report_claim is None:
        unmapped_errors.append(
            f"{claim['source_path']}:{claim['line']} missing in reports/capabilities.json"
        )
        continue

    linked_ids = report_claim.get("linked_capability_ids")
    if not isinstance(linked_ids, list) or not linked_ids:
        unmapped_errors.append(
            f"{claim['source_path']}:{claim['line']} has no linked_capability_ids"
        )
        continue

    missing_caps = [cap_id for cap_id in linked_ids if cap_id not in capabilities]
    if missing_caps:
        unmapped_errors.append(
            f"{claim['source_path']}:{claim['line']} references unknown capability ids: {', '.join(missing_caps)}"
        )
        continue

    if claim["risk_level"] != "high":
        continue

    for cap_id in linked_ids:
        overall_state = capabilities[cap_id].get("overall_state")
        if overall_state != "implemented_verified":
            high_risk_errors.append(
                f"{claim['source_path']}:{claim['line']} high-risk claim links {cap_id} ({overall_state})"
            )

if unmapped_errors:
    print("[claim-guard] unmapped claims detected:")
    for item in unmapped_errors:
        print(f"  - {item}")
    raise SystemExit(11)

if high_risk_errors:
    print("[claim-guard] high-risk claims blocked:")
    for item in high_risk_errors:
        print(f"  - {item}")
    raise SystemExit(10)

print(f"[claim-guard] PASS ({len(scanned_claims)} claims checked)")
raise SystemExit(0)
PY
