#!/usr/bin/env python3
"""Subset-schema pre-gate for REALITY/VLESS dry-run probes (R81).

R80 surfaced a tooling gap: the rust app's ``Config::load`` rejects
unknown fields at ``/outbounds/i/...`` (e.g. GUI-only ``__id_in_gui``),
but the ``reality_vless_probe_batch.py`` dry-run path never loads the
subset through the rust loader, so the rejection only fired at live
matrix time. R81 closes the gap by validating the subset schema in
the dry-run pre-gate stage.

The gate is REALITY/VLESS-scoped on purpose. The rust loader's
deny-unknown-fields check unions every protocol's fields, but a
REALITY/VLESS subset should only carry vless-shaped outbound
entries; tightening the allow-list here catches GUI-side residue
the rust loader would also reject.

Allow-list source:
- ``crates/sb-config/src/outbound/raw.rs::RawVlessConfig`` (the
  serde ``deny_unknown_fields`` boundary type).
- ``crates/sb-config/src/compat.rs::compat_v1_to_v2`` (the
  ``tag → name`` and ``server_port → port`` aliases handled before
  strict validation).

The gate never reads or returns field values. Only JSON pointer
paths, field names, and redacted human reasons are surfaced.
Sensitive material (uuid, public_key, short_id, server_name,
server, tag, password) stays in the local input file.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any, Iterable

# Mirror crates/sb-config/src/outbound/raw.rs::RawVlessConfig (HEAD
# b9729f52). Compat aliases (``tag`` ↔ ``name``, ``server_port`` ↔
# ``port``) are accepted because compat::migrate_to_v2 normalizes
# them before strict validation. See crates/sb-config/src/compat.rs
# lines 121-138 for the renames.
_REALITY_VLESS_OUTBOUND_FIELDS: frozenset[str] = frozenset(
    {
        "type",
        "tag",
        "name",
        "server",
        "server_port",
        "port",
        "uuid",
        "flow",
        "network",
        "packet_encoding",
        "connect_timeout_sec",
        "tls",
        "transport",
        "multiplex",
    }
)

_DEFAULT_REJECTED_PREFIXES: tuple[str, ...] = ("__",)

REJECTED_PREFIX_REASON_FMT = (
    "field name has rejected prefix {prefix!r} (likely GUI-only field)"
)
NOT_IN_ALLOW_LIST_REASON = (
    "field is not in the REALITY/VLESS rust schema accepted set"
)
NON_VLESS_TYPE_REASON = (
    "outbound type is not 'vless'; this gate is scoped to REALITY/VLESS"
    " subsets"
)
OUTBOUND_NOT_OBJECT_REASON = "outbound entry is not a JSON object"
ROOT_NOT_OBJECT_REASON = "subset root must be a JSON object"
MISSING_OUTBOUNDS_REASON = "subset has no outbounds list"


def reality_vless_outbound_allowed_fields() -> frozenset[str]:
    """Return the canonical accepted field set for REALITY/VLESS outbounds.

    REALITY/VLESS-scoped on purpose; not a union over every protocol.
    """
    return _REALITY_VLESS_OUTBOUND_FIELDS


def _escape_pointer_token(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _check_outbound_level_field(
    field: str,
    *,
    allowed: Iterable[str],
    rejected_prefixes: Iterable[str],
) -> str | None:
    for prefix in rejected_prefixes:
        if prefix and field.startswith(prefix):
            return REJECTED_PREFIX_REASON_FMT.format(prefix=prefix)
    if field not in allowed:
        return NOT_IN_ALLOW_LIST_REASON
    return None


def _check_nested_field(
    field: str,
    *,
    rejected_prefixes: Iterable[str],
) -> str | None:
    for prefix in rejected_prefixes:
        if prefix and field.startswith(prefix):
            return REJECTED_PREFIX_REASON_FMT.format(prefix=prefix)
    return None


def _walk_for_nested_violations(
    value: Any,
    *,
    json_pointer: str,
    rejected_prefixes: Iterable[str],
) -> list[dict[str, str]]:
    violations: list[dict[str, str]] = []
    if isinstance(value, dict):
        for child_key, child_value in value.items():
            if not isinstance(child_key, str):
                continue
            child_pointer = (
                f"{json_pointer}/{_escape_pointer_token(child_key)}"
            )
            reason = _check_nested_field(
                child_key, rejected_prefixes=rejected_prefixes
            )
            if reason is not None:
                violations.append(
                    {
                        "path": child_pointer,
                        "field": child_key,
                        "reason": reason,
                    }
                )
                continue
            violations.extend(
                _walk_for_nested_violations(
                    child_value,
                    json_pointer=child_pointer,
                    rejected_prefixes=rejected_prefixes,
                )
            )
    elif isinstance(value, list):
        for index, item in enumerate(value):
            child_pointer = f"{json_pointer}/{index}"
            violations.extend(
                _walk_for_nested_violations(
                    item,
                    json_pointer=child_pointer,
                    rejected_prefixes=rejected_prefixes,
                )
            )
    return violations


def _validate_outbound_entry(
    outbound: Any,
    *,
    index: int,
    allowed: frozenset[str],
    rejected_prefixes: Iterable[str],
) -> list[dict[str, str]]:
    if not isinstance(outbound, dict):
        return [
            {
                "path": f"/outbounds/{index}",
                "field": "(outbound)",
                "reason": OUTBOUND_NOT_OBJECT_REASON,
            }
        ]
    if outbound.get("type") != "vless":
        return [
            {
                "path": f"/outbounds/{index}/type",
                "field": "type",
                "reason": NON_VLESS_TYPE_REASON,
            }
        ]
    violations: list[dict[str, str]] = []
    for key, value in outbound.items():
        if not isinstance(key, str):
            continue
        outbound_pointer = (
            f"/outbounds/{index}/{_escape_pointer_token(key)}"
        )
        reason = _check_outbound_level_field(
            key, allowed=allowed, rejected_prefixes=rejected_prefixes
        )
        if reason is not None:
            violations.append(
                {
                    "path": outbound_pointer,
                    "field": key,
                    "reason": reason,
                }
            )
            continue
        violations.extend(
            _walk_for_nested_violations(
                value,
                json_pointer=outbound_pointer,
                rejected_prefixes=rejected_prefixes,
            )
        )
    return violations


def _classify_violation_depth(path: str) -> str:
    # /outbounds/{i}/{field} → 3 slashes → outbound level
    # /outbounds/{i}/{field}/... → 4+ slashes → nested
    # /outbounds/{i} (entry not an object) → 2 slashes → outbound level
    depth = path.count("/")
    return "outbound_level" if depth <= 3 else "nested"


def validate_subset_schema(
    subset_path: pathlib.Path | str,
    *,
    allowed_outbound_fields: Iterable[str] | None = None,
    rejected_field_prefixes: Iterable[str] = _DEFAULT_REJECTED_PREFIXES,
) -> dict[str, Any]:
    """Validate a REALITY/VLESS subset before live probe.

    Returns::

        {
          "ok": bool,
          "violations": [
            {"path": "/outbounds/0/__id_in_gui",
             "field": "__id_in_gui",
             "reason": "..."},
            ...
          ],
          "stats": {
            "outbounds_checked": int,
            "outbound_level_violations": int,
            "nested_violations": int,
          },
        }

    The gate never reads or returns field values; only the JSON
    pointer path, field name, and a redacted human reason appear.

    The gate does not modify the input file.
    """
    path = pathlib.Path(subset_path)
    text = path.read_text(encoding="utf-8")
    payload = json.loads(text)
    if not isinstance(payload, dict):
        return {
            "ok": False,
            "violations": [
                {
                    "path": "/",
                    "field": "(root)",
                    "reason": ROOT_NOT_OBJECT_REASON,
                }
            ],
            "stats": {
                "outbounds_checked": 0,
                "outbound_level_violations": 1,
                "nested_violations": 0,
            },
        }

    outbounds = payload.get("outbounds")
    if not isinstance(outbounds, list):
        return {
            "ok": False,
            "violations": [
                {
                    "path": "/outbounds",
                    "field": "outbounds",
                    "reason": MISSING_OUTBOUNDS_REASON,
                }
            ],
            "stats": {
                "outbounds_checked": 0,
                "outbound_level_violations": 1,
                "nested_violations": 0,
            },
        }

    allowed = (
        frozenset(allowed_outbound_fields)
        if allowed_outbound_fields is not None
        else _REALITY_VLESS_OUTBOUND_FIELDS
    )
    rejected_prefixes = tuple(rejected_field_prefixes)

    violations: list[dict[str, str]] = []
    outbound_level = 0
    nested = 0
    for index, outbound in enumerate(outbounds):
        outbound_violations = _validate_outbound_entry(
            outbound,
            index=index,
            allowed=allowed,
            rejected_prefixes=rejected_prefixes,
        )
        for violation in outbound_violations:
            if _classify_violation_depth(violation["path"]) == "nested":
                nested += 1
            else:
                outbound_level += 1
        violations.extend(outbound_violations)

    return {
        "ok": not violations,
        "violations": violations,
        "stats": {
            "outbounds_checked": len(outbounds),
            "outbound_level_violations": outbound_level,
            "nested_violations": nested,
        },
    }
