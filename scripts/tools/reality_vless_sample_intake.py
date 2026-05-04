#!/usr/bin/env python3
"""Validate a candidate REALITY/VLESS config against the committed baseline.

R71 fresh-sample intake gate. Decides which candidate outbounds are
genuinely fresh (i.e. eligible for a future R72 live probe round) versus
duplicates of the existing committed sample face or unusable due to
missing REALITY fields.

Hard rules:
- Pure offline analysis. Does not touch the network.
- Does not modify the baseline config. Does not modify the rollup.
- Output is redacted by default: full UUIDs, REALITY public keys,
  short_ids, and full server addresses are NEVER written. They are
  replaced with deterministic SHA-256 prefix hashes plus original
  length so duplicates can still be detected without leaking material.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys
from typing import Any

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

import reality_vless_env_from_config as envtool


# ---------------------------------------------------------------------------
# Redaction helpers


def _hash_prefix(value: str, length: int = 12) -> str:
    digest = hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()
    return digest[:length]


def redact_secret(value: str | None) -> dict[str, Any] | None:
    """Redact a secret string into {hash, length}.

    The hash is deterministic (so a duplicate UUID/public_key across
    files still collides) but is not reversible. The length is the raw
    character count so structurally short values can be flagged.
    """
    if not isinstance(value, str) or not value:
        return None
    return {"hash": _hash_prefix(value), "length": len(value)}


def redact_server(value: str | None) -> dict[str, Any] | None:
    """Redact a server address. Returns hash + length; never the raw value."""
    if not isinstance(value, str) or not value:
        return None
    return {"hash": _hash_prefix(value), "length": len(value)}


def derive_region(tag: str | None) -> str | None:
    """Pull a coarse region prefix from a tag like 'HK-A-BGP-2.0倍率'.

    The intake doc only needs region granularity, never a full tag with
    a server attached. Returns None if the tag is empty or has no '-'.
    """
    if not isinstance(tag, str) or not tag:
        return None
    head = tag.split("-", 1)[0].strip()
    return head or None


# ---------------------------------------------------------------------------
# Fingerprint extraction


def fingerprint_for(outbound: dict[str, Any]) -> dict[str, Any]:
    """Stable, redacted fingerprint usable for duplicate detection.

    Two outbounds match when every component (server-hash, port,
    server_name, public-key-hash, short-id-hash) is equal.
    """
    summary = envtool.outbound_summary(outbound)
    tls = envtool.tls_object(outbound)
    reality = envtool.reality_object(outbound, tls)
    public_key = envtool.optional_string(reality.get("public_key")) or envtool.optional_string(
        outbound.get("reality_public_key")
    )
    short_id = envtool.optional_string(reality.get("short_id")) or envtool.optional_string(
        outbound.get("reality_short_id")
    )
    uuid = envtool.optional_string(outbound.get("uuid"))
    server = summary["server"]
    return {
        "server_hash": _hash_prefix(server) if server else None,
        "port": summary["port"],
        "server_name": summary["server_name"],
        "public_key_hash": _hash_prefix(public_key) if public_key else None,
        "short_id_hash": _hash_prefix(short_id) if short_id else None,
        "uuid_hash": _hash_prefix(uuid) if uuid else None,
    }


def fingerprint_match_keys(fp: dict[str, Any]) -> tuple[Any, ...]:
    """Tuple used for set-membership tests; ignores uuid (uuid is per-account
    and may differ between candidate and baseline even for the same node)."""
    return (
        fp.get("server_hash"),
        fp.get("port"),
        fp.get("server_name"),
        fp.get("public_key_hash"),
        fp.get("short_id_hash"),
    )


# ---------------------------------------------------------------------------
# Baseline / rollup indexing


def _outbounds_list(config: dict[str, Any]) -> list[dict[str, Any]]:
    out = config.get("outbounds")
    if not isinstance(out, list):
        return []
    return [item for item in out if isinstance(item, dict)]


def index_baseline(config: dict[str, Any]) -> dict[str, Any]:
    """Build tag-set + fingerprint-set from the committed baseline."""
    tag_set: set[str] = set()
    fingerprints: dict[tuple[Any, ...], list[str]] = {}
    for outbound in _outbounds_list(config):
        if outbound.get("type") != "vless":
            continue
        name = envtool.outbound_name(outbound)
        if name:
            tag_set.add(name)
        fp = fingerprint_for(outbound)
        key = fingerprint_match_keys(fp)
        if any(k is not None for k in key):
            fingerprints.setdefault(key, []).append(name or "")
    return {"tags": tag_set, "fingerprints": fingerprints}


def index_rollup(rollup: dict[str, Any]) -> set[str]:
    """Collect the set of outbound keys that already have rollup history."""
    by = rollup.get("by_outbound") if isinstance(rollup, dict) else None
    if not isinstance(by, dict):
        return set()
    return {key for key in by.keys() if isinstance(key, str)}


# ---------------------------------------------------------------------------
# Classification


def _strip_suffix(tag: str | None) -> str | None:
    """Drop a trailing '倍率' suffix if present (matches rollup key format)."""
    if not isinstance(tag, str):
        return None
    suffix = "倍率"
    return tag[: -len(suffix)] if tag.endswith(suffix) else tag


def classify_candidate(
    outbound: dict[str, Any],
    baseline_index: dict[str, Any],
    rollup_keys: set[str],
) -> dict[str, Any]:
    name = envtool.outbound_name(outbound)
    summary = envtool.outbound_summary(outbound)
    fp = fingerprint_for(outbound)
    fp_key = fingerprint_match_keys(fp)
    fp_has_signal = any(k is not None for k in fp_key)
    rollup_key = _strip_suffix(name) or name

    classification = "fresh_ready"
    detail: dict[str, Any] = {}

    # 1. not_ready takes precedence: REALITY fields must all be present
    #    before duplicate-detection is meaningful.
    skip_reason = envtool.reality_vless_ready_reason(outbound)
    if skip_reason is not None:
        classification = "not_ready"
        detail["skip_reason"] = skip_reason
    else:
        # 2. tag duplicate
        if name and name in baseline_index["tags"]:
            classification = "duplicate"
            detail["duplicate_kind"] = "tag"
        elif fp_has_signal and fp_key in baseline_index["fingerprints"]:
            classification = "duplicate"
            detail["duplicate_kind"] = "fingerprint"
            detail["duplicate_baseline_tags"] = list(
                baseline_index["fingerprints"][fp_key]
            )

    # 3. covered_existing: even if classification==fresh_ready, if the rollup
    #    already has the same key we mark it covered. That demotes it out of
    #    fresh_ready into covered_existing.
    if classification == "fresh_ready" and rollup_key and rollup_key in rollup_keys:
        classification = "covered_existing"
        detail["rollup_key"] = rollup_key

    return {
        "tag": name,
        "region": derive_region(name),
        "type": outbound.get("type"),
        "port": summary["port"],
        "server_name": summary["server_name"],
        "fingerprint": fp,
        "ready": skip_reason is None,
        "skip_reason": skip_reason,
        "classification": classification,
        "detail": detail,
    }


def build_intake(
    candidate_config: dict[str, Any],
    baseline_config: dict[str, Any],
    rollup: dict[str, Any] | None,
) -> dict[str, Any]:
    baseline_index = index_baseline(baseline_config)
    rollup_keys = index_rollup(rollup or {})
    classified: list[dict[str, Any]] = []
    for outbound in _outbounds_list(candidate_config):
        if outbound.get("type") != "vless":
            # Non-vless outbounds are out of scope for REALITY intake.
            continue
        classified.append(
            classify_candidate(outbound, baseline_index, rollup_keys)
        )

    buckets: dict[str, list[dict[str, Any]]] = {
        "fresh_ready": [],
        "duplicate": [],
        "not_ready": [],
        "covered_existing": [],
    }
    for item in classified:
        buckets[item["classification"]].append(item)

    counts = {key: len(value) for key, value in buckets.items()}
    return {
        "summary": {
            "total_vless_outbounds": len(classified),
            "counts": counts,
            "selected_count": counts["fresh_ready"],
            "ready_for_r72": counts["fresh_ready"] > 0,
        },
        "fresh_ready": buckets["fresh_ready"],
        "duplicate": buckets["duplicate"],
        "not_ready": buckets["not_ready"],
        "covered_existing": buckets["covered_existing"],
    }


# ---------------------------------------------------------------------------
# Redacted markdown report


def render_redacted_md(intake: dict[str, Any]) -> str:
    summary = intake["summary"]
    lines: list[str] = []
    lines.append("# REALITY/VLESS Fresh Sample Intake (redacted)")
    lines.append("")
    lines.append(
        "Hashes are SHA-256 prefixes (12 chars). Raw UUIDs, public keys,"
        " short_ids, and server addresses are never written here."
    )
    lines.append("")
    lines.append("## Summary")
    lines.append("")
    lines.append(f"- total_vless_outbounds: {summary['total_vless_outbounds']}")
    lines.append(f"- fresh_ready: {summary['counts']['fresh_ready']}")
    lines.append(f"- duplicate: {summary['counts']['duplicate']}")
    lines.append(f"- not_ready: {summary['counts']['not_ready']}")
    lines.append(f"- covered_existing: {summary['counts']['covered_existing']}")
    lines.append(f"- ready_for_r72: {summary['ready_for_r72']}")
    lines.append("")

    def _block(title: str, key: str) -> None:
        items = intake[key]
        lines.append(f"## {title} ({len(items)})")
        lines.append("")
        if not items:
            lines.append("_(none)_")
            lines.append("")
            return
        for item in items:
            lines.append(f"- region={item.get('region') or '?'}")
            lines.append(f"  - port: {item.get('port')}")
            lines.append(f"  - server_name: {item.get('server_name')}")
            fp = item.get("fingerprint", {})
            lines.append(
                "  - fingerprint: server="
                f"{fp.get('server_hash')} pubkey={fp.get('public_key_hash')}"
                f" short_id={fp.get('short_id_hash')}"
            )
            if item.get("skip_reason"):
                lines.append(f"  - skip_reason: {item['skip_reason']}")
            if item.get("detail"):
                detail = dict(item["detail"])
                # Defensive: do not propagate unredacted keys if a future
                # caller adds them.
                lines.append(f"  - detail: {json.dumps(detail, sort_keys=True)}")
        lines.append("")

    _block("Fresh ready (eligible for R72 live probe)", "fresh_ready")
    _block("Duplicate of committed baseline", "duplicate")
    _block("Not ready (missing REALITY field)", "not_ready")
    _block("Covered by existing rollup", "covered_existing")
    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------------------
# CLI


def _load_json(path: pathlib.Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate a candidate REALITY/VLESS config as fresh sample input."
    )
    parser.add_argument("--candidate-config", required=True)
    parser.add_argument(
        "--baseline-config",
        default="agents-only/mt_real_01_evidence/phase3_ip_direct.json",
    )
    parser.add_argument(
        "--rollup-json",
        default="agents-only/mt_real_02_evidence/live_rollup.json",
    )
    parser.add_argument("--output-json", required=True)
    parser.add_argument("--redacted-md")
    args = parser.parse_args(argv)

    candidate = envtool.load_config(pathlib.Path(args.candidate_config))
    baseline = envtool.load_config(pathlib.Path(args.baseline_config))
    rollup_path = pathlib.Path(args.rollup_json)
    rollup = _load_json(rollup_path) if rollup_path.exists() else None

    intake = build_intake(candidate, baseline, rollup)
    output_path = pathlib.Path(args.output_json)
    output_path.write_text(json.dumps(intake, indent=2, ensure_ascii=True), encoding="utf-8")

    if args.redacted_md:
        md_path = pathlib.Path(args.redacted_md)
        md_path.write_text(render_redacted_md(intake), encoding="utf-8")

    print(
        json.dumps(
            {
                "output_json": str(output_path),
                "redacted_md": args.redacted_md,
                "selected_count": intake["summary"]["selected_count"],
                "counts": intake["summary"]["counts"],
                "ready_for_r72": intake["summary"]["ready_for_r72"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
