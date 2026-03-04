#!/usr/bin/env python3
"""Evaluate /capabilities negotiation contract for gui_real_cert gate."""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request


def parse_semver_triplet(raw: str):
    parts = raw.split(".")
    if len(parts) != 3:
        return None
    try:
        return tuple(int(p) for p in parts)
    except ValueError:
        return None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate capability negotiation gate.")
    parser.add_argument("--core", required=True)
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--token", default="")
    parser.add_argument("--required", choices=("0", "1"), required=True)
    parser.add_argument("--timeout-sec", type=int, default=5)
    parser.add_argument("--out-json", required=True)
    parser.add_argument("--payload-file", default="")
    return parser


def write_and_exit(result: dict, out_json: str, code: int) -> None:
    with open(out_json, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    raise SystemExit(code)


def load_payload_from_http(
    result: dict, api_url: str, token: str, timeout: int
) -> tuple[dict | None, int]:
    api_url = api_url.rstrip("/")
    url = f"{api_url}/capabilities"
    result["url"] = url
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    request = urllib.request.Request(url, headers=headers, method="GET")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            result["http_status"] = resp.status
            payload = json.loads(resp.read().decode("utf-8", errors="ignore"))
            return payload, 0
    except urllib.error.HTTPError as exc:
        result["http_status"] = exc.code
        result["reason"] = f"http_error:{exc.code}"
        return None, 1
    except Exception as exc:  # noqa: BLE001
        result["reason"] = f"request_failed:{exc}"
        return None, 1


def load_payload_from_file(result: dict, payload_file: str) -> tuple[dict | None, int]:
    payload_path = os.path.abspath(payload_file)
    result["url"] = f"file://{payload_path}"
    try:
        with open(payload_path, "r", encoding="utf-8") as fh:
            payload = json.load(fh)
    except Exception as exc:  # noqa: BLE001
        result["reason"] = f"request_failed:{exc}"
        return None, 1
    result["http_status"] = 200
    return payload, 0


def evaluate_payload(result: dict, payload: dict) -> None:
    if not isinstance(payload, dict):
        result["reason"] = "invalid_payload:not_object"
        return

    result["checked"] = True
    contract_version = payload.get("contract_version")
    required_by_gui = payload.get("required_by_gui")
    breaking_changes = payload.get("breaking_changes")

    if not isinstance(contract_version, str):
        result["reason"] = "missing_contract_version"
        return
    if not isinstance(required_by_gui, dict):
        result["reason"] = "missing_required_by_gui"
        return
    if not isinstance(breaking_changes, list):
        result["reason"] = "missing_breaking_changes"
        return

    min_version = required_by_gui.get("min_contract_version")
    required_status = required_by_gui.get("status")
    result["contract_version"] = contract_version
    result["required_min_contract_version"] = (
        min_version if isinstance(min_version, str) else None
    )
    result["required_status"] = required_status if isinstance(required_status, str) else None
    result["breaking_changes_count"] = len(breaking_changes)

    actual_v = parse_semver_triplet(contract_version)
    min_v = parse_semver_triplet(min_version) if isinstance(min_version, str) else None
    if actual_v is None or min_v is None:
        result["reason"] = "invalid_semver"
    elif actual_v < min_v:
        result["reason"] = "contract_version_below_required"
    elif required_status != "ok":
        result["reason"] = f"required_status_not_ok:{required_status}"
    elif breaking_changes:
        result["reason"] = f"breaking_changes_non_empty:{len(breaking_changes)}"
    else:
        result["status"] = "ok"
        result["pass"] = True


def main() -> None:
    args = build_parser().parse_args()
    required = args.required == "1"
    result = {
        "core": args.core,
        "url": "",
        "required": required,
        "checked": False,
        "pass": False,
        "status": "unknown",
        "http_status": None,
        "contract_version": None,
        "required_min_contract_version": None,
        "required_status": None,
        "breaking_changes_count": None,
        "reason": "",
    }

    if args.payload_file:
        payload, load_err = load_payload_from_file(result, args.payload_file)
    else:
        payload, load_err = load_payload_from_http(
            result, args.api_url, args.token, args.timeout_sec
        )

    if load_err != 0:
        if required:
            result["status"] = "blocked"
            write_and_exit(result, args.out_json, 1)
        result["status"] = "optional-unavailable"
        result["pass"] = True
        write_and_exit(result, args.out_json, 0)

    assert payload is not None
    evaluate_payload(result, payload)
    if result["pass"]:
        write_and_exit(result, args.out_json, 0)

    if required:
        result["status"] = "blocked"
        write_and_exit(result, args.out_json, 1)

    result["status"] = "optional-invalid"
    result["pass"] = True
    write_and_exit(result, args.out_json, 0)


if __name__ == "__main__":
    main()
