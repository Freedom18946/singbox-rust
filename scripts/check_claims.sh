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
    "docs/README.md",
    "docs/STATUS.md",
    "docs/MIGRATION_GUIDE.md",
    "docs/migration-from-go.md",
    "docs/00-getting-started/README.md",
    "docs/configuration.md",
    "docs/capabilities.md",
]

high_risk_patterns = [
    re.compile(r"production ready", re.IGNORECASE),
    re.compile(r"release[- ]ready", re.IGNORECASE),
    re.compile(r"full support", re.IGNORECASE),
    re.compile(r"27\+\s*fingerprints?", re.IGNORECASE),
    re.compile(r"(?:\bECH\b.*\bComplete\b|\bComplete\b.*\bECH\b)", re.IGNORECASE),
    re.compile(r"TUN,\s*Redirect,\s*TProxy.*✅", re.IGNORECASE),
]

closure_patterns = [
    re.compile(r"209/209", re.IGNORECASE),
    re.compile(r"100%\s*parity", re.IGNORECASE),
    re.compile(r"feature parity", re.IGNORECASE),
    re.compile(r"100%\s*protocol coverage", re.IGNORECASE),
    re.compile(r"acceptance baseline", re.IGNORECASE),
]


def classify_risk(text: str) -> str | None:
    if any(pattern.search(text) for pattern in high_risk_patterns):
        return "high"
    if any(pattern.search(text) for pattern in closure_patterns):
        return "medium"
    return None


def classify_claim_kind(text: str) -> str:
    if any(pattern.search(text) for pattern in closure_patterns):
        return "closure"
    return "capability"


def expected_utls_profile_ids(text: str) -> list[str]:
    lower = text.lower()
    expected: list[str] = []
    if re.search(r"\bchrome(?:\d+|_psk|_pq|_auto)?\b", lower):
        expected.append("tls.utls.chrome")
    if re.search(r"\bfirefox(?:\d+|_auto)?\b", lower):
        expected.append("tls.utls.firefox")
    if re.search(r"\brandom(?:ized|_chrome|_firefox)?\b", lower):
        expected.append("tls.utls.randomized")
    return expected


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
                    "claim_kind": classify_claim_kind(text),
                }
            )
    return out


def key_of(claim: dict[str, object]) -> tuple[str, int, str]:
    return (str(claim["source_path"]), int(claim["line"]), str(claim["text"]))


report = json.loads(report_path.read_text(encoding="utf-8"))
capabilities = {
    cap["id"]: cap for cap in report.get("capabilities", []) if isinstance(cap, dict) and "id" in cap
}
acceptance_closure = report.get("acceptance_closure")
if not isinstance(acceptance_closure, dict):
    print("[claim-guard] missing acceptance_closure in reports/capabilities.json")
    raise SystemExit(12)

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
closure_errors: list[str] = []

for claim in scanned_claims:
    k = key_of(claim)
    report_claim = report_claims.get(k)
    if report_claim is None:
        unmapped_errors.append(
            f"{claim['source_path']}:{claim['line']} missing in reports/capabilities.json"
        )
        continue

    linked_ids = report_claim.get("linked_ids")
    if not isinstance(linked_ids, list) or not linked_ids:
        unmapped_errors.append(f"{claim['source_path']}:{claim['line']} has no linked_ids")
        continue

    if report_claim.get("claim_kind") != claim["claim_kind"]:
        unmapped_errors.append(
            f"{claim['source_path']}:{claim['line']} claim_kind drift: expected {claim['claim_kind']}, got {report_claim.get('claim_kind')}"
        )
        continue

    if claim["claim_kind"] == "closure":
        if "acceptance_closure" not in linked_ids:
            closure_errors.append(
                f"{claim['source_path']}:{claim['line']} closure claim is not linked to acceptance_closure"
            )
        if acceptance_closure.get("status") != "evidence_backed":
            closure_errors.append(
                f"{claim['source_path']}:{claim['line']} closure claim blocked while acceptance_closure.status={acceptance_closure.get('status')}"
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

    if re.search(r"\butls\b", str(claim["text"]), re.IGNORECASE) or re.search(
        r"fingerprint", str(claim["text"]), re.IGNORECASE
    ):
        for expected_id in expected_utls_profile_ids(str(claim["text"])):
            if expected_id not in linked_ids:
                high_risk_errors.append(
                    f"{claim['source_path']}:{claim['line']} missing profile-linked capability {expected_id}"
                )

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

if closure_errors:
    print("[claim-guard] closure claims blocked:")
    for item in closure_errors:
        print(f"  - {item}")
    raise SystemExit(13)

print(f"[claim-guard] PASS ({len(scanned_claims)} claims checked)")
raise SystemExit(0)
PY
