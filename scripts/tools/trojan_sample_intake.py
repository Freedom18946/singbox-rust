#!/usr/bin/env python3
"""Validate Trojan fresh sample configs without leaking node material.

MT-TROJAN-FRESH-01 intake gate. This tool is intentionally offline: it
parses a candidate sing-box-style config, classifies Trojan outbounds,
and emits only redacted fingerprints. It never opens a network
connection and never writes raw server, password, or TLS server_name
values to its outputs.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
from typing import Any


def _hash_prefix(value: str, length: int = 12) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:length]


def optional_string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def optional_port(outbound: dict[str, Any]) -> int | None:
    value = outbound.get("server_port", outbound.get("port"))
    return value if isinstance(value, int) and 0 < value <= 65535 else None


def outbound_name(outbound: dict[str, Any]) -> str | None:
    value = outbound.get("tag", outbound.get("name"))
    return value if isinstance(value, str) and value else None


def tls_object(outbound: dict[str, Any]) -> dict[str, Any] | None:
    tls = outbound.get("tls")
    if tls is None:
        return {}
    return tls if isinstance(tls, dict) else None


def trojan_server_name(outbound: dict[str, Any], tls: dict[str, Any]) -> str | None:
    return optional_string(tls.get("server_name")) or optional_string(outbound.get("tls_sni"))


def fingerprint_for(outbound: dict[str, Any]) -> dict[str, Any]:
    tls = tls_object(outbound) or {}
    server = optional_string(outbound.get("server"))
    password = optional_string(outbound.get("password"))
    server_name = trojan_server_name(outbound, tls)
    return {
        "server_hash": _hash_prefix(server) if server else None,
        "port": optional_port(outbound),
        "password_hash": _hash_prefix(password) if password else None,
        "server_name_hash": _hash_prefix(server_name) if server_name else None,
    }


def fingerprint_match_key(fp: dict[str, Any]) -> tuple[Any, ...]:
    return (
        fp.get("server_hash"),
        fp.get("port"),
        fp.get("password_hash"),
        fp.get("server_name_hash"),
    )


def tls_skip_reason(outbound: dict[str, Any]) -> str | None:
    tls = outbound.get("tls")
    if tls is None:
        return None
    if not isinstance(tls, dict):
        return "invalid_tls"
    enabled = tls.get("enabled")
    if enabled is not None and not isinstance(enabled, bool):
        return "invalid_tls_enabled"
    server_name = tls.get("server_name")
    if server_name is not None and not isinstance(server_name, str):
        return "invalid_tls_server_name"
    return None


def trojan_ready_reason(outbound: dict[str, Any]) -> str | None:
    if outbound.get("type") != "trojan":
        return "not_trojan"
    if not optional_string(outbound.get("server")):
        return "missing_server"
    if optional_port(outbound) is None:
        return "missing_port"
    if not optional_string(outbound.get("password")):
        return "missing_password"
    return tls_skip_reason(outbound)


def _outbounds_list(config: dict[str, Any]) -> list[dict[str, Any]]:
    outbounds = config.get("outbounds")
    if not isinstance(outbounds, list):
        return []
    return [item for item in outbounds if isinstance(item, dict)]


def classify_candidates(config: dict[str, Any]) -> dict[str, Any]:
    buckets: dict[str, list[dict[str, Any]]] = {
        "trojan_ready": [],
        "duplicate": [],
        "not_ready": [],
        "unsupported": [],
    }
    seen_tags: dict[str, int] = {}
    seen_fingerprints: dict[tuple[Any, ...], int] = {}

    for index, outbound in enumerate(_outbounds_list(config)):
        name = outbound_name(outbound)
        tls = tls_object(outbound) or {}
        fp = fingerprint_for(outbound)
        item = {
            "index": index,
            "tag": name,
            "type": outbound.get("type"),
            "port": optional_port(outbound),
            "tls_enabled": tls.get("enabled") if isinstance(tls.get("enabled"), bool) else None,
            "fingerprint": fp,
            "ready": False,
            "skip_reason": None,
            "classification": None,
            "detail": {},
        }

        reason = trojan_ready_reason(outbound)
        if reason == "not_trojan":
            item["skip_reason"] = reason
            item["classification"] = "unsupported"
            buckets["unsupported"].append(item)
            continue
        if reason is not None:
            item["skip_reason"] = reason
            item["classification"] = "not_ready"
            buckets["not_ready"].append(item)
            continue

        if name and name in seen_tags:
            item["classification"] = "duplicate"
            item["detail"] = {
                "duplicate_kind": "tag",
                "duplicate_first_index": seen_tags[name],
            }
            buckets["duplicate"].append(item)
            continue

        fp_key = fingerprint_match_key(fp)
        if all(value is not None for value in fp_key) and fp_key in seen_fingerprints:
            item["classification"] = "duplicate"
            item["detail"] = {
                "duplicate_kind": "fingerprint",
                "duplicate_first_index": seen_fingerprints[fp_key],
            }
            buckets["duplicate"].append(item)
            continue

        item["ready"] = True
        item["classification"] = "trojan_ready"
        buckets["trojan_ready"].append(item)
        if name:
            seen_tags[name] = index
        if all(value is not None for value in fp_key):
            seen_fingerprints[fp_key] = index

    counts = {key: len(value) for key, value in buckets.items()}
    return {
        "summary": {
            "total_outbounds": len(_outbounds_list(config)),
            "counts": counts,
            "selected_count": counts["trojan_ready"],
            "ready_for_trojan_sanity": counts["trojan_ready"] > 0,
        },
        "trojan_ready": buckets["trojan_ready"],
        "duplicate": buckets["duplicate"],
        "not_ready": buckets["not_ready"],
        "unsupported": buckets["unsupported"],
    }


def render_redacted_md(intake: dict[str, Any]) -> str:
    summary = intake["summary"]
    counts = summary["counts"]
    lines: list[str] = [
        "# Trojan Fresh Sample Intake (redacted)",
        "",
        "Hashes are SHA-256 prefixes (12 chars). Raw server, password,",
        "and TLS server_name values are never written here.",
        "",
        "## Summary",
        "",
        f"- total_outbounds: {summary['total_outbounds']}",
        f"- trojan_ready: {counts['trojan_ready']}",
        f"- duplicate: {counts['duplicate']}",
        f"- not_ready: {counts['not_ready']}",
        f"- unsupported: {counts['unsupported']}",
        f"- ready_for_trojan_sanity: {summary['ready_for_trojan_sanity']}",
        "",
    ]

    def block(title: str, key: str) -> None:
        items = intake[key]
        lines.append(f"## {title} ({len(items)})")
        lines.append("")
        if not items:
            lines.append("_(none)_")
            lines.append("")
            return
        for item in items:
            lines.append(f"- tag={item.get('tag') or '?'}")
            lines.append(f"  - port: {item.get('port')}")
            lines.append(f"  - tls_enabled: {item.get('tls_enabled')}")
            fp = item.get("fingerprint", {})
            lines.append(
                "  - fingerprint: server="
                f"{fp.get('server_hash')} password={fp.get('password_hash')}"
                f" server_name={fp.get('server_name_hash')}"
            )
            if item.get("skip_reason"):
                lines.append(f"  - skip_reason: {item['skip_reason']}")
            if item.get("detail"):
                lines.append(f"  - detail: {json.dumps(item['detail'], sort_keys=True)}")
        lines.append("")

    block("Trojan ready", "trojan_ready")
    block("Duplicate", "duplicate")
    block("Not ready", "not_ready")
    block("Unsupported", "unsupported")
    return "\n".join(lines).rstrip() + "\n"


def load_config(path: pathlib.Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit("config root must be an object")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate Trojan candidate config with redacted output."
    )
    parser.add_argument("--candidate-config", required=True)
    parser.add_argument("--output-json", required=True)
    parser.add_argument("--redacted-md")
    args = parser.parse_args(argv)

    intake = classify_candidates(load_config(pathlib.Path(args.candidate_config)))
    output_path = pathlib.Path(args.output_json)
    output_path.write_text(json.dumps(intake, indent=2, ensure_ascii=True), encoding="utf-8")
    if args.redacted_md:
        pathlib.Path(args.redacted_md).write_text(render_redacted_md(intake), encoding="utf-8")

    print(
        json.dumps(
            {
                "output_json": str(output_path),
                "redacted_md": args.redacted_md,
                "selected_count": intake["summary"]["selected_count"],
                "counts": intake["summary"]["counts"],
                "ready_for_trojan_sanity": intake["summary"]["ready_for_trojan_sanity"],
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
