#!/usr/bin/env python3
"""Sanitized external REALITY fallback/camouflage observation.

The probe sends an ordinary, unauthenticated TLS ClientHello to each configured
REALITY endpoint. A conforming server rejects REALITY authentication and relays
that connection to its configured target. TLS/HTTP observations are also
collected from the configured SNI through public DNS on TCP/443. This is an
oracle candidate, not proof of the server's private target address.

Output deliberately excludes endpoints, SNI, UUIDs, public keys, short IDs,
certificate bytes/hashes, and exception messages. It reports only neutral node
ids, protocol facts, boolean comparisons, timing, and sanitized error classes.

This tool does NOT decide censorship-resistance or camouflage sufficiency. It
can only observe a subset of upstream XTLS target guidance: TLS 1.3, H2, and no
disallowed domain redirect (main-to-www is allowed).
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as dt
import hashlib
import json
import pathlib
import socket
import ssl
import statistics
import time
from typing import Any
from urllib.parse import urlsplit

UPSTREAM_REALITY_COMMIT = "9234c772ba8f181f31c3e81dc2b4177322e5a9a9"
UPSTREAM_README_SHA256 = (
    "5658a983b4335f8af1e0e24edba51fc1f50f57b0e6826660f14b65b5c5800c13"
)
SCOPE_NOTE = (
    "Observes ordinary-TLS fallback and the network-visible subset of upstream "
    "target guidance from one vantage point. Does not classify GFW location, "
    "prove censorship-resistance, traffic-distribution equivalence, or "
    "real-network camouflage sufficiency."
)


def _optional_string(value: Any) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _outbound_name(outbound: dict[str, Any], index: int) -> str:
    return (
        _optional_string(outbound.get("name"))
        or _optional_string(outbound.get("tag"))
        or f"outbound-{index + 1:03d}"
    )


def _port(outbound: dict[str, Any]) -> int | None:
    value = outbound.get("port", outbound.get("server_port"))
    if isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 65535:
        return value
    return None


def _plain_tcp(outbound: dict[str, Any]) -> bool:
    transport = outbound.get("transport")
    if transport is None:
        return True
    return isinstance(transport, dict) and transport.get("type") in (None, "tcp")


def _reality_object(outbound: dict[str, Any]) -> dict[str, Any]:
    tls = outbound.get("tls")
    if not isinstance(tls, dict):
        return {}
    reality = tls.get("reality")
    return reality if isinstance(reality, dict) else {}


def _server_name(outbound: dict[str, Any]) -> str | None:
    tls = outbound.get("tls")
    tls = tls if isinstance(tls, dict) else {}
    reality = _reality_object(outbound)
    return (
        _optional_string(reality.get("server_name"))
        or _optional_string(tls.get("server_name"))
        or _optional_string(tls.get("sni"))
        or _optional_string(outbound.get("reality_server_name"))
        or _optional_string(outbound.get("tls_sni"))
        or _optional_string(outbound.get("server"))
    )


def _ready_reason(outbound: dict[str, Any]) -> str | None:
    if outbound.get("type") != "vless":
        return "not_vless"
    if not _plain_tcp(outbound):
        return "not_plain_tcp"
    if _optional_string(outbound.get("server")) is None:
        return "missing_server"
    if _port(outbound) is None:
        return "missing_port"
    if _server_name(outbound) is None:
        return "missing_server_name"
    reality = _reality_object(outbound)
    if reality.get("enabled") is not True and not _optional_string(
        reality.get("public_key")
    ):
        return "reality_not_enabled"
    return None


def load_candidates(path: pathlib.Path) -> tuple[str, list[dict[str, Any]]]:
    raw_bytes = path.read_bytes()
    root = json.loads(raw_bytes)
    if isinstance(root, list):
        outbounds = root
    elif isinstance(root, dict) and isinstance(root.get("outbounds"), list):
        outbounds = root["outbounds"]
    else:
        raise ValueError("config must be an outbound array or object with outbounds")

    candidates: list[dict[str, Any]] = []
    for index, value in enumerate(outbounds):
        if not isinstance(value, dict):
            continue
        source_name = _outbound_name(value, index)
        candidates.append(
            {
                "index": index,
                "source_name": source_name,
                "source_name_hash": hashlib.sha256(
                    source_name.encode("utf-8")
                ).hexdigest()[:12],
                "server": _optional_string(value.get("server")),
                "port": _port(value),
                "server_name": _server_name(value),
                "ready_reason": _ready_reason(value),
            }
        )
    return f"sha256:{hashlib.sha256(raw_bytes).hexdigest()}", candidates


def select_candidates(
    candidates: list[dict[str, Any]],
    requested: list[str],
    requested_indexes: list[int],
    limit: int | None,
) -> list[dict[str, Any]]:
    ready = [item for item in candidates if item["ready_reason"] is None]
    if requested:
        if len(requested) != len(set(requested)):
            raise ValueError("requested outbound names must be unique")
        matches = [
            [item for item in ready if item["source_name"] == name]
            for name in requested
        ]
        missing_count = sum(not group for group in matches)
        ambiguous_count = sum(len(group) > 1 for group in matches)
        if missing_count:
            raise ValueError(
                f"requested outbound count not ready/found: {missing_count}"
            )
        if ambiguous_count:
            raise ValueError(f"requested outbound names ambiguous: {ambiguous_count}")
        ready = [group[0] for group in matches]
    elif requested_indexes:
        if len(requested_indexes) != len(set(requested_indexes)):
            raise ValueError("requested source indexes must be unique")
        by_index = {item["index"] + 1: item for item in ready}
        missing_count = sum(index not in by_index for index in requested_indexes)
        if missing_count:
            raise ValueError(
                f"requested source index count not ready/found: {missing_count}"
            )
        ready = [by_index[index] for index in requested_indexes]
    if limit is not None:
        ready = ready[:limit]
    selected: list[dict[str, Any]] = []
    for sequence, item in enumerate(ready, 1):
        selected.append({**item, "node_id": f"cam-{sequence:03d}"})
    return selected


def _context(alpn: list[str]) -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.set_alpn_protocols(alpn)
    return context


def _tls_handshake(host: str, port: int, server_name: str, timeout: float) -> dict[str, Any]:
    started = time.monotonic()
    with socket.create_connection((host, port), timeout=timeout) as raw:
        raw.settimeout(timeout)
        with _context(["h2", "http/1.1"]).wrap_socket(
            raw, server_hostname=server_name
        ) as stream:
            cert = stream.getpeercert(binary_form=True)
            cipher = stream.cipher()
            return {
                "tls_ok": True,
                "tls_version": stream.version(),
                "cipher": cipher[0] if cipher else None,
                "alpn": stream.selected_alpn_protocol(),
                "handshake_ms": round((time.monotonic() - started) * 1000, 3),
                "_leaf_sha256": hashlib.sha256(cert).hexdigest(),
            }


def _disallowed_domain_redirect(server_name: str, location: str | None) -> bool:
    if not location:
        return False
    redirect_host = urlsplit(location).hostname
    if not redirect_host:
        return False
    source = server_name.lower().removeprefix("www.")
    destination = redirect_host.lower().removeprefix("www.")
    return source != destination


def _http_head(host: str, port: int, server_name: str, timeout: float) -> dict[str, Any]:
    with socket.create_connection((host, port), timeout=timeout) as raw:
        raw.settimeout(timeout)
        with _context(["http/1.1"]).wrap_socket(
            raw, server_hostname=server_name
        ) as stream:
            request = (
                f"HEAD / HTTP/1.1\r\nHost: {server_name}\r\n"
                "User-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n"
            ).encode("ascii")
            stream.sendall(request)
            data = bytearray()
            while b"\r\n\r\n" not in data and len(data) < 32768:
                chunk = stream.recv(4096)
                if not chunk:
                    break
                data.extend(chunk)
    head = bytes(data).split(b"\r\n\r\n", 1)[0].decode("iso-8859-1")
    lines = head.split("\r\n")
    if not lines or not lines[0].startswith("HTTP/"):
        raise ValueError("invalid HTTP response")
    parts = lines[0].split()
    if len(parts) < 2 or not parts[1].isdigit():
        raise ValueError("invalid HTTP status")
    status = int(parts[1])
    location: str | None = None
    for line in lines[1:]:
        name, separator, value = line.partition(":")
        if separator and name.strip().lower() == "location":
            location = value.strip()
            break
    redirect = 300 <= status < 400
    disallowed_domain_redirect = redirect and _disallowed_domain_redirect(
        server_name, location
    )
    return {
        "http_ok": True,
        "http_status": status,
        "http_redirect": redirect,
        "disallowed_domain_redirect": disallowed_domain_redirect,
    }


def _error_class(error: BaseException) -> str:
    if isinstance(error, (TimeoutError, socket.timeout)):
        return "timeout"
    if isinstance(error, ssl.SSLCertVerificationError):
        return "certificate_verification"
    if isinstance(error, ssl.SSLError):
        return "tls_error"
    if isinstance(error, socket.gaierror):
        return "dns_error"
    if isinstance(error, ConnectionRefusedError):
        return "connection_refused"
    if isinstance(error, ConnectionResetError):
        return "connection_reset"
    if isinstance(error, OSError):
        return "network_error"
    return "protocol_error"


def _probe_side(host: str, port: int, server_name: str, timeout: float) -> dict[str, Any]:
    result: dict[str, Any]
    try:
        result = _tls_handshake(host, port, server_name, timeout)
    except Exception as error:  # boundary: sanitize every network failure
        result = {"tls_ok": False, "tls_error_class": _error_class(error)}
    try:
        result.update(_http_head(host, port, server_name, timeout))
    except Exception as error:  # boundary: sanitize every network failure
        result.update({"http_ok": False, "http_error_class": _error_class(error)})
    return result


def _public_side(side: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in side.items() if not key.startswith("_")}


def probe_pair(candidate: dict[str, Any], run: int, timeout: float) -> dict[str, Any]:
    proxy = _probe_side(
        candidate["server"], candidate["port"], candidate["server_name"], timeout
    )
    oracle = _probe_side(candidate["server_name"], 443, candidate["server_name"], timeout)
    comparison = {
        "leaf_cert_equal": bool(
            proxy.get("_leaf_sha256")
            and proxy.get("_leaf_sha256") == oracle.get("_leaf_sha256")
        ),
        "tls_version_equal": bool(
            proxy.get("tls_version")
            and proxy.get("tls_version") == oracle.get("tls_version")
        ),
        "cipher_equal": bool(
            proxy.get("cipher") and proxy.get("cipher") == oracle.get("cipher")
        ),
        "alpn_equal": bool(
            proxy.get("alpn") and proxy.get("alpn") == oracle.get("alpn")
        ),
    }
    return {
        "node_id": candidate["node_id"],
        "run": run,
        "proxy_fallback": _public_side(proxy),
        "direct_sni_oracle": _public_side(oracle),
        "comparison": comparison,
    }


def _side_minimum(side: dict[str, Any]) -> bool:
    return bool(
        side.get("tls_ok")
        and side.get("tls_version") == "TLSv1.3"
        and side.get("alpn") == "h2"
        and side.get("http_ok")
        and side.get("disallowed_domain_redirect") is False
    )


def summarize_node(node_id: str, runs: list[dict[str, Any]]) -> dict[str, Any]:
    proxy_times = [
        item["proxy_fallback"]["handshake_ms"]
        for item in runs
        if isinstance(item["proxy_fallback"].get("handshake_ms"), (int, float))
    ]
    oracle_times = [
        item["direct_sni_oracle"]["handshake_ms"]
        for item in runs
        if isinstance(item["direct_sni_oracle"].get("handshake_ms"), (int, float))
    ]
    minimum_runs = sum(
        _side_minimum(item["proxy_fallback"])
        and _side_minimum(item["direct_sni_oracle"])
        for item in runs
    )
    return {
        "node_id": node_id,
        "run_count": len(runs),
        "proxy_verified_tls_runs": sum(item["proxy_fallback"].get("tls_ok") is True for item in runs),
        "oracle_verified_tls_runs": sum(
            item["direct_sni_oracle"].get("tls_ok") is True for item in runs
        ),
        "proxy_tls13_h2_runs": sum(
            item["proxy_fallback"].get("tls_version") == "TLSv1.3"
            and item["proxy_fallback"].get("alpn") == "h2"
            for item in runs
        ),
        "oracle_tls13_h2_runs": sum(
            item["direct_sni_oracle"].get("tls_version") == "TLSv1.3"
            and item["direct_sni_oracle"].get("alpn") == "h2"
            for item in runs
        ),
        "proxy_no_disallowed_domain_redirect_runs": sum(
            item["proxy_fallback"].get("http_ok") is True
            and item["proxy_fallback"].get("disallowed_domain_redirect") is False
            for item in runs
        ),
        "oracle_no_disallowed_domain_redirect_runs": sum(
            item["direct_sni_oracle"].get("http_ok") is True
            and item["direct_sni_oracle"].get("disallowed_domain_redirect") is False
            for item in runs
        ),
        "exact_leaf_match_runs": sum(item["comparison"]["leaf_cert_equal"] for item in runs),
        "exact_tls_profile_match_runs": sum(
            item["comparison"]["tls_version_equal"]
            and item["comparison"]["cipher_equal"]
            and item["comparison"]["alpn_equal"]
            for item in runs
        ),
        "upstream_observable_minimum_observed_runs": minimum_runs,
        "proxy_handshake_median_ms": round(statistics.median(proxy_times), 3)
        if proxy_times
        else None,
        "oracle_handshake_median_ms": round(statistics.median(oracle_times), 3)
        if oracle_times
        else None,
        "runs": runs,
    }


def summarize(nodes: list[dict[str, Any]]) -> dict[str, Any]:
    total_runs = sum(node["run_count"] for node in nodes)
    observed_runs = sum(
        node["upstream_observable_minimum_observed_runs"] for node in nodes
    )
    complete_pair_runs = sum(
        item["proxy_fallback"].get("tls_ok") is True
        and item["direct_sni_oracle"].get("tls_ok") is True
        for node in nodes
        for item in node["runs"]
    )
    if total_runs == 0 or complete_pair_runs == 0:
        observation = "INCONCLUSIVE"
    elif observed_runs == total_runs:
        observation = "UPSTREAM_OBSERVABLE_MINIMUM_OBSERVED"
    else:
        observation = "UPSTREAM_OBSERVABLE_MINIMUM_NOT_FULLY_OBSERVED"
    return {
        "node_count": len(nodes),
        "total_pair_runs": total_runs,
        "complete_tls_pair_runs": complete_pair_runs,
        "upstream_observable_minimum_observed_runs": observed_runs,
        "observation": observation,
        "camouflage_sufficiency_verdict": "NOT_ASSESSED",
    }


def _dry_run_record(
    fingerprint: str, candidates: list[dict[str, Any]], selected: list[dict[str, Any]]
) -> dict[str, Any]:
    return {
        "schema_version": 1,
        "dry_run": True,
        "source_fingerprint": fingerprint,
        "candidate_count": len(candidates),
        "ready_count": sum(item["ready_reason"] is None for item in candidates),
        "selected": [
            {
                "node_id": item["node_id"],
                "source_name_hash": item["source_name_hash"],
                "ready": True,
            }
            for item in selected
        ],
        "scope_note": SCOPE_NOTE,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True, type=pathlib.Path)
    parser.add_argument("--outbound", action="append", default=[])
    parser.add_argument("--source-index", action="append", type=int, default=[])
    parser.add_argument("--limit", type=int)
    parser.add_argument("--runs", type=int, default=3)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--output-json", required=True, type=pathlib.Path)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    if args.runs < 1 or args.timeout <= 0 or args.workers < 1:
        parser.error("runs/workers must be positive and timeout must be > 0")
    if args.limit is not None and args.limit < 1:
        parser.error("limit must be positive")
    selection_modes = sum(
        bool(value) for value in (args.limit is not None, args.outbound, args.source_index)
    )
    if selection_modes > 1:
        parser.error("limit, outbound, and source-index are mutually exclusive")
    if any(index < 1 for index in args.source_index):
        parser.error("source-index is 1-based and must be positive")

    try:
        fingerprint, candidates = load_candidates(args.config)
        selected = select_candidates(
            candidates, args.outbound, args.source_index, args.limit
        )
    except (OSError, json.JSONDecodeError, ValueError) as error:
        parser.error(str(error))
    if not selected:
        parser.error("no ready REALITY/VLESS plain-TCP candidates")

    if args.dry_run:
        record = _dry_run_record(fingerprint, candidates, selected)
    else:
        pairs: list[tuple[dict[str, Any], int]] = [
            (candidate, run)
            for candidate in selected
            for run in range(1, args.runs + 1)
        ]
        by_node: dict[str, list[dict[str, Any]]] = {
            candidate["node_id"]: [] for candidate in selected
        }
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as executor:
            future_map = {
                executor.submit(probe_pair, candidate, run, args.timeout): (
                    candidate["node_id"],
                    run,
                )
                for candidate, run in pairs
            }
            for future in concurrent.futures.as_completed(future_map):
                node_id, _ = future_map[future]
                by_node[node_id].append(future.result())
        nodes = []
        for candidate in selected:
            runs = sorted(by_node[candidate["node_id"]], key=lambda item: item["run"])
            node = summarize_node(candidate["node_id"], runs)
            node["source_name_hash"] = candidate["source_name_hash"]
            nodes.append(node)
        record = {
            "schema_version": 1,
            "dry_run": False,
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "source_fingerprint": fingerprint,
            "upstream_provenance": {
                "repository": "XTLS/REALITY",
                "commit": UPSTREAM_REALITY_COMMIT,
                "readme_sha256": UPSTREAM_README_SHA256,
                "observable_target_properties": [
                    "tls_1_3",
                    "h2",
                    "no_disallowed_domain_redirect",
                ],
            },
            "nodes": nodes,
            "summary": summarize(nodes),
            "scope_note": SCOPE_NOTE,
        }

    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    print(
        json.dumps(
            {
                "output_json": str(args.output_json),
                "dry_run": args.dry_run,
                "selected_count": len(selected),
                "summary": record.get("summary"),
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
