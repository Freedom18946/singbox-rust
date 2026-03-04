#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

DOC_FILES = [
    "README.md",
    "docs/capabilities.md",
    "docs/STATUS.md",
    "docs/RUST_ENHANCEMENTS.md",
    "docs/07-reference/platform-io.md",
    "agents-only/01-spec/01-REQUIREMENTS-ANALYSIS.md",
    "agents-only/02-reference/GO_PARITY_MATRIX.md",
]

KNOWN_CAPABILITY_IDS = {
    "project.acceptance.baseline",
    "tun.macos.tun2socks",
    "inbound.redirect",
    "inbound.tproxy",
    "tls.utls",
    "tls.ech.tcp",
    "tls.ech.quic",
}

HIGH_RISK_PATTERNS = [
    re.compile(r"production ready", re.IGNORECASE),
    re.compile(r"full support", re.IGNORECASE),
    re.compile(r"27\+\s*fingerprints?", re.IGNORECASE),
    re.compile(r"(?:\bECH\b.*\bComplete\b|\bComplete\b.*\bECH\b)", re.IGNORECASE),
    re.compile(r"TUN,\s*Redirect,\s*TProxy.*✅", re.IGNORECASE),
]

MEDIUM_RISK_PATTERNS = [
    re.compile(r"209/209", re.IGNORECASE),
    re.compile(r"100%\s*parity", re.IGNORECASE),
    re.compile(r"feature parity", re.IGNORECASE),
    re.compile(r"100%\s*protocol coverage", re.IGNORECASE),
]

EXPLICIT_CAPABILITY_RE = re.compile(
    r"capability\s*[:：]\s*`?([a-z][a-z0-9_.-]+)`?",
    re.IGNORECASE,
)


def locate_line(path: Path, needle: str) -> int:
    if not path.exists():
        return 1
    for idx, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if needle in line:
            return idx
    return 1


def dedup_keep_order(values: list[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for value in values:
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def classify_risk(text: str) -> str | None:
    for pattern in HIGH_RISK_PATTERNS:
        if pattern.search(text):
            return "high"
    for pattern in MEDIUM_RISK_PATTERNS:
        if pattern.search(text):
            return "medium"
    return None


def derive_overall_state(compile_state: str, runtime_state: str, verification_state: str) -> str:
    if compile_state in {"stubbed", "absent"}:
        return "scaffold_stub"
    if runtime_state in {"unsupported", "blocked"}:
        return "scaffold_stub"
    if verification_state in {"e2e_verified", "integration_verified"} and runtime_state == "verified":
        return "implemented_verified"
    return "implemented_unverified"


def extract_explicit_capabilities(text: str) -> list[str]:
    explicit: list[str] = []
    for cap_id in EXPLICIT_CAPABILITY_RE.findall(text):
        if cap_id in KNOWN_CAPABILITY_IDS:
            explicit.append(cap_id)
    return dedup_keep_order(explicit)


def map_claim_to_capabilities(text: str) -> list[str]:
    lower = text.lower()
    mapped = extract_explicit_capabilities(text)

    if "tun, redirect, tproxy" in lower:
        mapped.extend([
            "tun.macos.tun2socks",
            "inbound.redirect",
            "inbound.tproxy",
        ])

    if re.search(r"\btun\b", lower):
        mapped.append("tun.macos.tun2socks")
    if re.search(r"\bredirect\b", lower):
        mapped.append("inbound.redirect")
    if re.search(r"\btproxy\b", lower):
        mapped.append("inbound.tproxy")

    if re.search(r"\butls\b", lower) or "fingerprint" in lower:
        mapped.append("tls.utls")

    if re.search(r"\bech\b", lower) and re.search(r"\bquic\b", lower):
        mapped.append("tls.ech.quic")
    elif re.search(r"\bech\b", lower):
        mapped.append("tls.ech.tcp")

    if (
        "209/209" in lower
        or "100% parity" in lower
        or "feature parity" in lower
        or "100% protocol coverage" in lower
        or "acceptance baseline" in lower
    ):
        mapped.append("project.acceptance.baseline")

    return dedup_keep_order(mapped)


def git_short_sha(root: Path) -> str:
    try:
        out = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"],
            cwd=root,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        return out.strip() or "unknown"
    except Exception:
        return "unknown"


def build_capabilities(root: Path) -> list[dict]:
    def ev(kind: str, rel_path: str, needle: str, note: str) -> dict:
        line = locate_line(root / rel_path, needle)
        return {
            "kind": kind,
            "path": rel_path,
            "line": line,
            "note": note,
        }

    capabilities = [
        {
            "id": "project.acceptance.baseline",
            "name": "Acceptance baseline closure accounting",
            "compile_state": "supported",
            "runtime_state": "verified",
            "verification_state": "integration_verified",
            "overall_state": "implemented_verified",
            "accepted_limitation": True,
            "evidence": [
                ev(
                    "doc",
                    "agents-only/02-reference/GO_PARITY_MATRIX.md",
                    "Current Parity",
                    "Baseline closure uses accepted limitations accounting.",
                )
            ],
        },
        {
            "id": "tun.macos.tun2socks",
            "name": "macOS tun2socks data-plane path",
            "compile_state": "stubbed",
            "runtime_state": "unsupported",
            "verification_state": "compile_only",
            "overall_state": "scaffold_stub",
            "accepted_limitation": True,
            "evidence": [
                ev(
                    "code",
                    "Cargo.toml",
                    "tun2socks = { path = \"vendor/tun2socks\" }",
                    "Workspace overrides tun2socks with local stub crate.",
                ),
                ev(
                    "code",
                    "vendor/tun2socks/src/lib.rs",
                    "pub fn main_from_str",
                    "Stub returns Ok(()) immediately and does not forward traffic.",
                ),
            ],
        },
        {
            "id": "inbound.redirect",
            "name": "Redirect inbound wiring",
            "compile_state": "gated_off",
            "runtime_state": "unsupported",
            "verification_state": "no_evidence",
            "overall_state": "scaffold_stub",
            "accepted_limitation": True,
            "evidence": [
                ev(
                    "doc",
                    "docs/07-reference/platform-io.md",
                    "redirect (iptables REDIRECT)",
                    "Documented as code exists but not wired in this build.",
                ),
                ev(
                    "code",
                    "app/src/inbound_starter.rs",
                    "InboundType::Redirect | InboundType::Tproxy",
                    "Runtime warns redirect is not supported in this build.",
                ),
            ],
        },
        {
            "id": "inbound.tproxy",
            "name": "TProxy inbound wiring",
            "compile_state": "gated_off",
            "runtime_state": "unsupported",
            "verification_state": "no_evidence",
            "overall_state": "scaffold_stub",
            "accepted_limitation": True,
            "evidence": [
                ev(
                    "doc",
                    "docs/07-reference/platform-io.md",
                    "tproxy (IP_TRANSPARENT)",
                    "Documented as code exists but not wired in this build.",
                ),
                ev(
                    "code",
                    "app/src/inbound_starter.rs",
                    "InboundType::Redirect | InboundType::Tproxy",
                    "Runtime warns tproxy is not supported in this build.",
                ),
            ],
        },
        {
            "id": "tls.utls",
            "name": "uTLS-style fingerprinting",
            "compile_state": "supported",
            "runtime_state": "unverified",
            "verification_state": "integration_verified",
            "overall_state": "implemented_unverified",
            "accepted_limitation": True,
            "evidence": [
                ev(
                    "code",
                    "crates/sb-tls/src/utls.rs",
                    "Suites not supported by rustls",
                    "Unsupported suites are skipped; behavior is best-effort.",
                ),
                ev(
                    "doc",
                    "crates/sb-tls/README.md",
                    "uTLS full ClientHello/extension ordering parity",
                    "Documented as partial parity due to rustls limitations.",
                ),
            ],
        },
        {
            "id": "tls.ech.tcp",
            "name": "TLS (TCP) client-side ECH",
            "compile_state": "supported",
            "runtime_state": "unverified",
            "verification_state": "integration_verified",
            "overall_state": "implemented_unverified",
            "accepted_limitation": True,
            "evidence": [
                ev(
                    "code",
                    "crates/sb-transport/src/tls.rs",
                    ".with_ech(ech_mode)",
                    "Rustls ECH mode is wired for TLS client config path.",
                ),
                ev(
                    "doc",
                    "crates/sb-tls/docs/ech_usage.md",
                    "client-side ECH integration",
                    "Documented as client-side TLS integration only.",
                ),
            ],
        },
        {
            "id": "tls.ech.quic",
            "name": "QUIC ECH alignment",
            "compile_state": "supported",
            "runtime_state": "unsupported",
            "verification_state": "no_evidence",
            "overall_state": "scaffold_stub",
            "accepted_limitation": True,
            "evidence": [
                ev(
                    "code",
                    "crates/sb-transport/src/quic.rs",
                    "Full ECH-QUIC integration requires custom QUIC crypto config",
                    "Current QUIC path is explicitly marked as simplified integration point.",
                ),
                ev(
                    "doc",
                    "crates/sb-tls/docs/ech_usage.md",
                    "Server-side ECH and QUIC ECH pending",
                    "ECH usage doc marks QUIC ECH as pending work.",
                ),
            ],
        },
    ]

    for capability in capabilities:
        capability["overall_state"] = derive_overall_state(
            capability["compile_state"],
            capability["runtime_state"],
            capability["verification_state"],
        )

    return capabilities


def extract_claims(root: Path) -> list[dict]:
    claims: list[dict] = []
    for rel_path in DOC_FILES:
        file_path = root / rel_path
        if not file_path.exists():
            continue
        for line_no, raw in enumerate(file_path.read_text(encoding="utf-8").splitlines(), start=1):
            text = raw.strip()
            if not text:
                continue
            risk = classify_risk(text)
            if risk is None:
                continue
            claims.append(
                {
                    "source_path": rel_path,
                    "line": line_no,
                    "text": text,
                    "risk_level": risk,
                    "linked_capability_ids": map_claim_to_capabilities(text),
                }
            )
    return claims


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate capabilities report")
    parser.add_argument(
        "--out",
        default="reports/capabilities.json",
        help="Output path (default: reports/capabilities.json)",
    )
    parser.add_argument(
        "--profile",
        default="docs-only",
        help="Profile tag in report metadata",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(__file__).resolve().parents[2]
    out_path = (root / args.out).resolve()

    payload = {
        "schema_version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source_commit": git_short_sha(root),
        "profile": args.profile,
        "capabilities": build_capabilities(root),
        "claims": extract_claims(root),
    }

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"[capabilities] wrote {out_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
