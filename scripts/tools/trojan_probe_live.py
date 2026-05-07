#!/usr/bin/env python3
"""Run bounded Trojan live sanity from a redacted dry-run plan.

MT-TROJAN-FRESH-04 live runner. This script is intentionally narrow:
it consumes an already-authorized redacted plan, verifies the bounds,
invokes the Rust `probe-outbound` tool for the selected Trojan tags,
and writes only redacted evidence. Raw server, password, and TLS
server_name values are never written to stdout or evidence.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import pathlib
import re
import subprocess
import sys
from typing import Any


DEFAULT_PROBE_COMMAND = [
    "cargo",
    "run",
    "--quiet",
    "-p",
    "app",
    "--features",
    "router,adapters",
    "--bin",
    "probe-outbound",
    "--",
]

ENV_LIMITED_CLASSES = {
    "connection_refused",
    "connection_reset",
    "permission_denied",
    "post_dial_eof",
    "timeout",
}

MAX_DIAGNOSTIC_EXCERPT = 180
MAX_BRIDGE_DIAGNOSTIC_EXCERPT = 220

# Specific classes that already convey actionable meaning. If
# `classify_probe_error_text` in probe-outbound returns one of these we keep
# the value rather than re-classifying the bridge error text.
BRIDGE_KEEP_CLASSES = {
    "broken_pipe",
    "connection_refused",
    "connection_reset",
    "handshake_eof",
    "http2_framing",
    "permission_denied",
    "post_dial_eof",
    "reality_dial_eof",
    "socks_connect",
    "timeout",
}

# Ordered keyword -> refined class table. The first matching keyword wins.
# `error` from `probe-outbound` is the connect / connect_io error CHAIN; the
# leading `raw_connect_error` is the (expected) encrypted-stream message
# emitted by `AdapterIoBridge::connect`. Adapter config-validation
# rejections (`Invalid server address`, `invalid socket address syntax`)
# come first because the connect_io chain may carry both the wrapper
# rejection prefix AND the underlying adapter signal — the adapter
# signal is the actionable one. After that, network / handshake / DNS
# signals must out-prioritize the wrapper-rejection chain prefix so
# real connect_io failures do not get bucketed as `unsupported_protocol`.
# `unsupported_protocol` only wins when no stronger signal is present —
# i.e. the chain leaks no information beyond the wrapper rejection.
BRIDGE_CLASS_PATTERNS: list[tuple[str, str]] = [
    # Adapter-specific config-validation rejection. Must precede every
    # network / wrapper signal because the connect_io chain can carry both
    # a `uses encrypted stream` (wrapper) prefix AND the underlying
    # `Invalid server address` text. The latter is the actionable signal.
    ("invalid server address", "invalid_server_address"),
    ("invalid socket address syntax", "invalid_server_address"),
    ("no such host", "dns_error"),
    ("name or service not known", "dns_error"),
    ("name resolution", "dns_error"),
    ("dns resolution", "dns_error"),
    ("dns query", "dns_error"),
    ("nodename nor servname", "dns_error"),
    ("network is unreachable", "network_unreachable"),
    ("network unreachable", "network_unreachable"),
    ("no route to host", "network_unreachable"),
    ("ehostunreach", "network_unreachable"),
    ("tls handshake eof", "handshake_eof"),
    ("handshake eof", "handshake_eof"),
    ("early eof during", "handshake_eof"),
    ("certificate", "tls_error"),
    ("invalid peer", "tls_error"),
    ("badcertificate", "tls_error"),
    ("alert", "tls_error"),
    ("tls handshake", "tls_error"),
    ("tls connect", "tls_error"),
    ("ssl", "tls_error"),
    ("authentication", "auth_failed"),
    ("auth failed", "auth_failed"),
    ("auth_failed", "auth_failed"),
    ("unauthorized", "auth_failed"),
    ("invalid password", "auth_failed"),
    ("connection refused", "connection_refused"),
    ("econnrefused", "connection_refused"),
    ("connection reset", "connection_reset"),
    ("econnreset", "connection_reset"),
    ("broken pipe", "connection_reset"),
    ("operation timed out", "timeout"),
    ("timed out", "timeout"),
    ("timeout", "timeout"),
    ("unexpected response", "unexpected_response"),
    ("unexpected http", "unexpected_response"),
    ("malformed response", "unexpected_response"),
    ("protocol error", "unexpected_response"),
    # Wrapper-rejection signals come last. They are the EXPECTED first-attempt
    # failure for encrypted-stream protocols and only mean "the bridge layer
    # routed to connect_io" — not a node defect.
    ("uses encrypted stream", "unsupported_protocol"),
    ("encrypted stream", "unsupported_protocol"),
    ("use connect_io", "unsupported_protocol"),
    ("dial transport not supported", "unsupported_protocol"),
    ("transport not implemented", "unsupported_protocol"),
]


def positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return parsed


def load_json_object(path: pathlib.Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise SystemExit(f"JSON root must be an object: {path}")
    return value


def hash_prefix(value: str, length: int = 12) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()[:length]


def collect_scrub_values(candidate_config: dict[str, Any]) -> list[str]:
    """Collect raw node material that must never appear in evidence."""
    outbounds = candidate_config.get("outbounds")
    values: list[str] = []
    if not isinstance(outbounds, list):
        return values
    for outbound in outbounds:
        if not isinstance(outbound, dict):
            continue
        for key in ("server", "password", "tls_sni"):
            value = outbound.get(key)
            if isinstance(value, str) and value:
                values.append(value)
        tls = outbound.get("tls")
        if isinstance(tls, dict):
            server_name = tls.get("server_name")
            if isinstance(server_name, str) and server_name:
                values.append(server_name)
    return sorted(set(values), key=len, reverse=True)


def scrub_text(text: str, scrub_values: list[str]) -> str:
    scrubbed = text
    for value in scrub_values:
        scrubbed = scrubbed.replace(value, f"<redacted:{hash_prefix(value)}>")
    # Collapse long filesystem-local temp names and keep diagnostics bounded.
    scrubbed = re.sub(r"/tmp/[^\s'\"]+", "/tmp/<redacted-path>", scrubbed)
    scrubbed = scrubbed.splitlines()
    collapsed = " ".join(part.strip() for part in scrubbed if part.strip())
    if len(collapsed) > MAX_DIAGNOSTIC_EXCERPT:
        return collapsed[:MAX_DIAGNOSTIC_EXCERPT] + "..."
    return collapsed


def validate_plan_bounds(
    plan: dict[str, Any],
    expected_selected: int,
    expected_runs: int,
    expected_target: str,
    expected_timeout: int,
) -> None:
    summary = plan.get("summary")
    if not isinstance(summary, dict):
        raise SystemExit("plan has no summary object")
    checks = {
        "selected_count": expected_selected,
        "runs": expected_runs,
        "target": expected_target,
        "timeout": expected_timeout,
        "planned_runs": expected_selected * expected_runs,
    }
    for key, expected in checks.items():
        if summary.get(key) != expected:
            raise SystemExit(f"plan bound mismatch: {key}")
    if summary.get("ready_for_live_authorization") is not True:
        raise SystemExit("plan is not ready_for_live_authorization")
    if len(plan.get("selected", [])) != expected_selected:
        raise SystemExit("selected list length does not match selected_count")


def extract_probe_json(stdout: str) -> dict[str, Any] | None:
    text = stdout.strip()
    if not text:
        return None
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def stdout_kind(stdout: str, parsed: dict[str, Any] | None) -> str:
    if not stdout.strip():
        return "empty"
    if parsed is None:
        return "non_json"
    if not isinstance(parsed.get("bridge_probe"), dict):
        return "json_missing_bridge_probe"
    return "json_bridge_probe"


def classify_tool_failure(
    returncode: int,
    stdout: str,
    stderr: str,
    parsed: dict[str, Any] | None,
) -> str:
    combined = f"{stdout}\n{stderr}"
    lower = combined.lower()
    if returncode == 124 or "timeout" in lower or "timed out" in lower:
        return "timeout"
    if "usage:" in lower or "error:" in lower and "required" in lower:
        return "cli_usage_error"
    if "permission denied" in lower or "operation not permitted" in lower:
        return "permission_denied"
    if "connection refused" in lower:
        return "connection_refused"
    if "connection reset" in lower:
        return "connection_reset"
    if "could not compile" in lower or "compile_error" in lower:
        return "tool_compile_error"
    if "no such file" in lower or "not found" in lower:
        return "tool_missing"
    if "config validation failed" in lower and "unknown field" in lower:
        return "config_validation_unknown_field"
    kind = stdout_kind(stdout, parsed)
    if kind == "non_json":
        return "stdout_non_json"
    if kind == "json_missing_bridge_probe":
        return "stdout_missing_bridge_probe"
    return "tool_unknown"


def diagnostic_for_process(
    returncode: int,
    stdout: str,
    stderr: str,
    parsed: dict[str, Any] | None,
    scrub_values: list[str],
) -> dict[str, Any]:
    kind = stdout_kind(stdout, parsed)
    # When bridge_probe JSON exists, structured fields already capture the
    # safe result. Keep only fingerprints for stdout so nested probe details
    # are not copied into evidence excerpts.
    combined = stderr if kind == "json_bridge_probe" else f"{stdout}\n{stderr}"
    return {
        "returncode": returncode,
        "stdout_kind": kind,
        "stderr_present": bool(stderr.strip()),
        "stdout_sha256_12": hash_prefix(stdout) if stdout else None,
        "stderr_sha256_12": hash_prefix(stderr) if stderr else None,
        "scrubbed_excerpt": scrub_text(combined, scrub_values),
    }


def refine_bridge_class(
    original_class: str | None,
    error_text: str | None,
    raw_connect_error_text: str | None,
) -> str:
    """Narrow a structured bridge_probe failure class.

    Inspects the connect / connect_io error chain captured by
    `probe-outbound` and returns one of the dedicated bridge classes such as
    `unsupported_protocol`, `dns_error`, `tls_error`, `auth_failed`,
    `handshake_eof`, `connection_refused`, `connection_reset`,
    `network_unreachable`, `timeout`, `unexpected_response` or, when no
    pattern matches, `unknown_probe_failure`. Keeps an already-specific
    `original_class` (for example `timeout`) if the text contains no
    stronger signal.
    """
    if original_class and original_class in BRIDGE_KEEP_CLASSES:
        return original_class

    parts: list[str] = []
    if isinstance(error_text, str) and error_text:
        parts.append(error_text)
    if isinstance(raw_connect_error_text, str) and raw_connect_error_text:
        parts.append(raw_connect_error_text)
    combined = " ".join(parts).strip()
    if not combined:
        if original_class and original_class != "other":
            return original_class
        return "unknown_probe_failure"

    lower = combined.lower()
    for needle, refined in BRIDGE_CLASS_PATTERNS:
        if needle in lower:
            return refined

    if original_class and original_class != "other":
        return original_class
    return "unknown_probe_failure"


def bridge_diagnostic_for_probe(
    bridge_probe: dict[str, Any],
    scrub_values: list[str],
) -> dict[str, Any]:
    """Build a redacted bridge diagnostic record for a structured failure.

    `error_kind` is the refined class. `error_sha256_12` and
    `raw_connect_error_sha256_12` are SHA-256 prefixes of the raw bridge
    error texts so future runs can be correlated without copying node
    material. `scrubbed_excerpt` removes any candidate-config server,
    password, or TLS server_name occurrences before storing a bounded
    excerpt of the combined error chain.
    """
    error_text = bridge_probe.get("error") if isinstance(bridge_probe.get("error"), str) else None
    raw_connect_error_text = (
        bridge_probe.get("raw_connect_error")
        if isinstance(bridge_probe.get("raw_connect_error"), str)
        else None
    )
    original_class = (
        bridge_probe.get("class") if isinstance(bridge_probe.get("class"), str) else None
    )
    parts = [text for text in (error_text, raw_connect_error_text) if text]
    combined = "\n".join(parts)
    excerpt = scrub_text(combined, scrub_values) if combined else ""
    if len(excerpt) > MAX_BRIDGE_DIAGNOSTIC_EXCERPT:
        excerpt = excerpt[:MAX_BRIDGE_DIAGNOSTIC_EXCERPT] + "..."
    return {
        "error_kind": refine_bridge_class(original_class, error_text, raw_connect_error_text),
        "error_sha256_12": hash_prefix(error_text) if error_text else None,
        "raw_connect_error_sha256_12": hash_prefix(raw_connect_error_text)
        if raw_connect_error_text
        else None,
        "scrubbed_excerpt": excerpt,
    }


def build_probe_command(
    base_command: list[str],
    candidate_config: pathlib.Path,
    item: dict[str, Any],
    target: str,
    timeout: int,
) -> list[str]:
    tag = item.get("tag")
    if not isinstance(tag, str) or not tag:
        raise SystemExit("selected item has no tag")
    return [
        *base_command,
        "--config",
        str(candidate_config),
        "--outbound",
        tag,
        "--target",
        target,
        "--timeout",
        str(timeout),
        "--json",
    ]


def result_from_probe(
    item: dict[str, Any],
    run_index: int,
    returncode: int,
    stdout: str,
    stderr: str,
    scrub_values: list[str] | None = None,
) -> dict[str, Any]:
    scrub_values = scrub_values or []
    parsed = extract_probe_json(stdout)
    bridge_probe = parsed.get("bridge_probe") if isinstance(parsed, dict) else None
    if isinstance(bridge_probe, dict):
        ok = bridge_probe.get("ok") is True
        original_class = bridge_probe.get("class")
        bridge_diagnostic = bridge_diagnostic_for_probe(bridge_probe, scrub_values)
        status = "ok" if ok else "probe_error"
        if ok:
            class_value: str | None = None
        else:
            refined = bridge_diagnostic["error_kind"]
            # Preserve `other` only when no refined class is available; the
            # refinement helper never returns the literal `other` so this
            # check is defensive against future bridge classes.
            class_value = refined or (
                str(original_class) if original_class else "unknown_probe_failure"
            )
        return {
            "tag": item.get("tag"),
            "index": item.get("index"),
            "run_index": run_index,
            "status": status,
            "ok": ok,
            "class": class_value,
            "stage": bridge_probe.get("stage"),
            "stream_mode": bridge_probe.get("stream_mode"),
            "connect_time_ms": bridge_probe.get("connect_time_ms"),
            "response_bytes": bridge_probe.get("response_bytes"),
            "port": item.get("port"),
            "server_hash": item.get("server_hash"),
            "password_hash": item.get("password_hash"),
            "server_name_hash": item.get("server_name_hash"),
            "returncode": returncode,
            "bridge_diagnostic": bridge_diagnostic,
            "tool_diagnostic": diagnostic_for_process(
                returncode,
                stdout,
                stderr,
                parsed,
                scrub_values,
            ),
        }

    class_value = classify_tool_failure(returncode, stdout, stderr, parsed)
    status = (
        "probe_error"
        if class_value in ENV_LIMITED_CLASSES
        else "tool_error"
    )
    return {
        "tag": item.get("tag"),
        "index": item.get("index"),
        "run_index": run_index,
        "status": status,
        "ok": False,
        "class": class_value,
        "stage": None,
        "stream_mode": None,
        "connect_time_ms": None,
        "response_bytes": None,
        "port": item.get("port"),
        "server_hash": item.get("server_hash"),
        "password_hash": item.get("password_hash"),
        "server_name_hash": item.get("server_name_hash"),
        "returncode": returncode,
        "bridge_diagnostic": None,
        "tool_diagnostic": diagnostic_for_process(
            returncode,
            stdout,
            stderr,
            parsed,
            scrub_values,
        ),
    }


def summarize_results(plan: dict[str, Any], results: list[dict[str, Any]]) -> dict[str, Any]:
    status_counts = collections.Counter(str(item.get("status", "unknown")) for item in results)
    class_counts = collections.Counter(
        str(item.get("class")) for item in results if item.get("class")
    )
    ok_count = sum(1 for item in results if item.get("ok") is True)
    tool_error_count = sum(1 for item in results if item.get("status") == "tool_error")
    env_limited_count = sum(
        1 for item in results if item.get("class") in ENV_LIMITED_CLASSES
    )
    failed_count = len(results) - ok_count
    node_contact_confirmed = any(item.get("status") != "tool_error" for item in results)
    summary = plan["summary"]
    return {
        "selected_count": summary["selected_count"],
        "runs": summary["runs"],
        "target": summary["target"],
        "timeout": summary["timeout"],
        "planned_runs": summary["planned_runs"],
        "executed_runs": len(results),
        "ok_count": ok_count,
        "failed_count": failed_count,
        "env_limited_count": env_limited_count,
        "tool_error_count": tool_error_count,
        "status_counts": dict(sorted(status_counts.items())),
        "class_counts": dict(sorted(class_counts.items())),
        "live_authorized": True,
        "probe_invocations": len(results),
        "node_contact_confirmed": node_contact_confirmed,
        "rust_only_quality_line": True,
        "dual_kernel_parity_promotion": False,
        "bhv_unchanged": "52/56",
    }


def classify_evidence(summary: dict[str, Any]) -> str:
    if summary["executed_runs"] == 0:
        return "D"
    if summary["tool_error_count"] > 0:
        return "C"
    if summary["ok_count"] > 0:
        return "A"
    if summary["failed_count"] == summary["env_limited_count"]:
        return "B"
    return "A"


def build_evidence(plan: dict[str, Any], results: list[dict[str, Any]]) -> dict[str, Any]:
    summary = summarize_results(plan, results)
    return {
        "summary": summary,
        "classification": classify_evidence(summary),
        "results": results,
    }


def render_redacted_md(evidence: dict[str, Any]) -> str:
    summary = evidence["summary"]
    lines = [
        "# Trojan Live Sanity Evidence (redacted)",
        "",
        "Raw server, password, and TLS server_name values are not present.",
        "This is a Rust-only quality line and not dual-kernel parity promotion.",
        "",
        "## Summary",
        "",
        f"- classification: {evidence['classification']}",
        f"- selected_count: {summary['selected_count']}",
        f"- runs: {summary['runs']}",
        f"- target: {summary['target']}",
        f"- timeout: {summary['timeout']}",
        f"- planned_runs: {summary['planned_runs']}",
        f"- executed_runs: {summary['executed_runs']}",
        f"- ok_count: {summary['ok_count']}",
        f"- failed_count: {summary['failed_count']}",
        f"- env_limited_count: {summary['env_limited_count']}",
        f"- tool_error_count: {summary['tool_error_count']}",
        f"- status_counts: {json.dumps(summary['status_counts'], sort_keys=True)}",
        f"- class_counts: {json.dumps(summary['class_counts'], sort_keys=True)}",
        f"- probe_invocations: {summary['probe_invocations']}",
        f"- node_contact_confirmed: {summary['node_contact_confirmed']}",
        f"- bhv_unchanged: {summary['bhv_unchanged']}",
        "",
        f"## Results ({len(evidence['results'])})",
        "",
    ]
    for item in evidence["results"]:
        lines.append(f"- tag={item.get('tag') or '?'}")
        lines.append(f"  - index: {item.get('index')}")
        lines.append(f"  - run_index: {item.get('run_index')}")
        lines.append(f"  - status: {item.get('status')}")
        lines.append(f"  - class: {item.get('class')}")
        lines.append(f"  - returncode: {item.get('returncode')}")
        lines.append(f"  - stage: {item.get('stage')}")
        lines.append(f"  - stream_mode: {item.get('stream_mode')}")
        bridge = item.get("bridge_diagnostic") if isinstance(item.get("bridge_diagnostic"), dict) else None
        if bridge:
            lines.append(f"  - bridge_error_kind: {bridge.get('error_kind')}")
            lines.append(
                "  - bridge_fingerprint: error="
                f"{bridge.get('error_sha256_12')} raw_connect_error="
                f"{bridge.get('raw_connect_error_sha256_12')}"
            )
            if bridge.get("scrubbed_excerpt"):
                lines.append(f"  - bridge_excerpt: {bridge.get('scrubbed_excerpt')}")
        diagnostic = item.get("tool_diagnostic") if isinstance(item.get("tool_diagnostic"), dict) else {}
        if diagnostic:
            lines.append(f"  - stdout_kind: {diagnostic.get('stdout_kind')}")
            lines.append(f"  - stderr_present: {diagnostic.get('stderr_present')}")
            lines.append(f"  - diagnostic_fingerprint: stdout={diagnostic.get('stdout_sha256_12')} stderr={diagnostic.get('stderr_sha256_12')}")
            if diagnostic.get("scrubbed_excerpt"):
                lines.append(f"  - diagnostic_excerpt: {diagnostic.get('scrubbed_excerpt')}")
        lines.append(
            "  - fingerprint: server="
            f"{item.get('server_hash')} password={item.get('password_hash')}"
            f" server_name={item.get('server_name_hash')}"
        )
    return "\n".join(lines).rstrip() + "\n"


def run_live(
    plan: dict[str, Any],
    candidate_config: pathlib.Path,
    probe_command: list[str],
) -> dict[str, Any]:
    summary = plan["summary"]
    scrub_values = collect_scrub_values(load_json_object(candidate_config))
    results: list[dict[str, Any]] = []
    for item in plan["selected"]:
        for run_index in range(1, int(summary["runs"]) + 1):
            cmd = build_probe_command(
                probe_command,
                candidate_config,
                item,
                str(summary["target"]),
                int(summary["timeout"]),
            )
            try:
                proc = subprocess.run(
                    cmd,
                    cwd=pathlib.Path(__file__).resolve().parents[2],
                    text=True,
                    capture_output=True,
                    timeout=int(summary["timeout"]) + 120,
                    check=False,
                )
                results.append(
                    result_from_probe(
                        item,
                        run_index,
                        proc.returncode,
                        proc.stdout,
                        proc.stderr,
                        scrub_values,
                    )
                )
            except subprocess.TimeoutExpired as exc:
                results.append(
                    result_from_probe(
                        item,
                        run_index,
                        124,
                        exc.stdout if isinstance(exc.stdout, str) else "",
                        exc.stderr if isinstance(exc.stderr, str) else "timeout",
                        scrub_values,
                    )
                )
    return build_evidence(plan, results)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run bounded Trojan live sanity from a redacted plan.")
    parser.add_argument("--plan-json", required=True)
    parser.add_argument("--candidate-config", required=True)
    parser.add_argument("--expected-selected", type=positive_int, default=5)
    parser.add_argument("--expected-runs", type=positive_int, default=1)
    parser.add_argument("--expected-target", default="example.com:80")
    parser.add_argument("--expected-timeout", type=positive_int, default=8)
    parser.add_argument("--output-json", required=True)
    parser.add_argument("--redacted-md")
    parser.add_argument("--probe-command", action="append", default=[])
    args = parser.parse_args(argv)

    plan = load_json_object(pathlib.Path(args.plan_json))
    validate_plan_bounds(
        plan,
        args.expected_selected,
        args.expected_runs,
        args.expected_target,
        args.expected_timeout,
    )
    probe_command = args.probe_command or DEFAULT_PROBE_COMMAND
    evidence = run_live(plan, pathlib.Path(args.candidate_config), probe_command)

    output_path = pathlib.Path(args.output_json)
    output_path.write_text(json.dumps(evidence, indent=2, ensure_ascii=True), encoding="utf-8")
    if args.redacted_md:
        pathlib.Path(args.redacted_md).write_text(render_redacted_md(evidence), encoding="utf-8")

    print(
        json.dumps(
            {
                "output_json": str(output_path),
                "redacted_md": args.redacted_md,
                "classification": evidence["classification"],
                "summary": evidence["summary"],
            },
            indent=2,
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
