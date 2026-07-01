#!/usr/bin/env python3
"""Validate Grafana dashboards, alert rules, and scrape-path docs."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
GRAFANA = ROOT / "grafana"
DASHBOARDS = GRAFANA / "dashboards"

IDENT = re.compile(r"(?<![A-Za-z0-9_:])([A-Za-z_:][A-Za-z0-9_:]*)(?![A-Za-z0-9_:])")
STRING = re.compile(r'"(?:\\.|[^"\\])*"')

SOURCE_METRIC_PATTERNS = [
    re.compile(r"(?:metrics::)?(?:counter|gauge|histogram)!\(\s*\"([A-Za-z_:][A-Za-z0-9_:]*)\"", re.S),
    re.compile(r"(?:^|[^A-Za-z0-9_:])(?:counter|gauge|histogram)!\(\s*\"([A-Za-z_:][A-Za-z0-9_:]*)\"", re.S),
    re.compile(r"\b(?:prometheus::)?(?:HistogramOpts|Opts)::new\(\s*\"([A-Za-z_:][A-Za-z0-9_:]*)\"", re.S),
    re.compile(r"\bget_or_register_[A-Za-z0-9_]+\(\s*\"([A-Za-z_:][A-Za-z0-9_:]*)\"", re.S),
    re.compile(r"\b(?:guarded|registered)_[A-Za-z0-9_]+\(\s*\"([A-Za-z_:][A-Za-z0-9_:]*)\"", re.S),
    re.compile(r"\b(?:IntCounter|IntGauge|Gauge|Histogram)::new\(\s*\"([A-Za-z_:][A-Za-z0-9_:]*)\"", re.S),
]

PROMQL_WORDS = {
    "abs",
    "avg",
    "bool",
    "by",
    "ceil",
    "clamp_min",
    "count",
    "floor",
    "group_left",
    "group_right",
    "histogram_quantile",
    "ignoring",
    "increase",
    "max",
    "min",
    "on",
    "or",
    "and",
    "rate",
    "sum",
    "topk",
    "vector",
    "without",
}

LABEL_KEYS = {
    "adapter",
    "category",
    "chan",
    "class",
    "code",
    "component",
    "dir",
    "endpoint",
    "from_cache",
    "kind",
    "le",
    "method",
    "mode",
    "operation",
    "outbound",
    "place",
    "protocol",
    "proxy",
    "qtype",
    "reason",
    "result",
    "severity",
    "shard",
    "state",
    "status",
}

FORBIDDEN_TEXT = {
    GRAFANA / "README.md": [
        "/__metrics",
        "SB_ADMIN_ENABLE",
        "SB_ADMIN_LISTEN",
        "18088",
        "grafana/grafana:latest",
        "prom/prometheus:latest",
    ],
    GRAFANA / "provisioning" / "datasources.yml": [
        "grafana/grafana:latest",
        "prom/prometheus:latest",
    ],
}

REQUIRED_TEXT = {
    GRAFANA / "README.md": [
        "metrics_path: /metricsz",
        "ADMIN_LISTEN=0.0.0.0:19090",
        "http://127.0.0.1:19090/metricsz",
        "SB_METRICS_ADDR=127.0.0.1:9090",
        "http://127.0.0.1:9090/metrics",
    ],
    ROOT / "docs" / "03-operations" / "monitoring" / "grafana-dashboards.md": [
        "ADMIN_LISTEN=0.0.0.0:19090",
        "http://singbox-rust:19090/metricsz",
        "python3 grafana/verify_metadata.py",
    ],
}


def fail(message: str) -> None:
    raise AssertionError(message)


def load_source_metric_names() -> set[str]:
    names: set[str] = set()
    source_roots = [crate / "src" for crate in (ROOT / "crates").iterdir() if (crate / "src").is_dir()]
    source_roots.append(ROOT / "app" / "src")
    for base in source_roots:
        for path in base.rglob("*.rs"):
            text = path.read_text(encoding="utf-8")
            for pattern in SOURCE_METRIC_PATTERNS:
                names.update(pattern.findall(text))
    return names


def strip_derived_suffix(metric: str) -> str:
    for suffix in ("_bucket", "_sum", "_count"):
        if metric.endswith(suffix):
            return metric[: -len(suffix)]
    return metric


def metric_known(metric: str, source_metrics: set[str]) -> bool:
    return metric in source_metrics or strip_derived_suffix(metric) in source_metrics


def iter_panels(panel_list: list[dict], prefix: str = ""):
    for index, panel in enumerate(panel_list):
        title = panel.get("title") or f"panel-{index}"
        path = f"{prefix}/{title}" if prefix else title
        yield path, panel
        nested = panel.get("panels")
        if isinstance(nested, list):
            yield from iter_panels(nested, path)


def panel_datasource(panel: dict, target: dict, dashboard: dict):
    return target.get("datasource") or panel.get("datasource") or dashboard.get("datasource")


def is_prometheus_datasource(value) -> bool:
    if isinstance(value, dict):
        return value.get("type") == "prometheus" and value.get("uid") == "${DS_PROMETHEUS}"
    if isinstance(value, str):
        return value in {"${DS_PROMETHEUS}", "Prometheus", "prometheus"}
    return False


def extract_promql_metrics(expr: str) -> set[str]:
    clean = STRING.sub('""', expr)
    metrics: set[str] = set()
    for match in IDENT.finditer(clean):
        token = match.group(1)
        if token in PROMQL_WORDS or token in LABEL_KEYS:
            continue
        after = clean[match.end() :].lstrip()
        inside_selector = clean.rfind("{", 0, match.start()) > clean.rfind("}", 0, match.start())
        if inside_selector and after.startswith(("=", "!=", "=~", "!~")):
            continue
        before = clean[: match.start()].rstrip()
        if before.endswith("$"):
            continue
        metrics.add(token)
    return metrics


def extract_alert_expressions(text: str) -> list[str]:
    expressions: list[str] = []
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        match = re.match(r"^(\s*)expr:\s*(.*)$", line)
        if not match:
            i += 1
            continue
        indent = len(match.group(1))
        rest = match.group(2).strip()
        if rest != "|":
            expressions.append(rest)
            i += 1
            continue
        i += 1
        block: list[str] = []
        while i < len(lines):
            child = lines[i]
            child_indent = len(child) - len(child.lstrip(" "))
            if child.strip() and child_indent <= indent:
                break
            block.append(child[indent + 2 :] if len(child) >= indent + 2 else child)
            i += 1
        expressions.append("\n".join(block))
    return expressions


def validate_dashboard(path: Path, source_metrics: set[str]) -> list[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    errors: list[str] = []
    if not data.get("uid"):
        errors.append(f"{path}: missing dashboard uid")
    if not data.get("title"):
        errors.append(f"{path}: missing dashboard title")

    variables = data.get("templating", {}).get("list", [])
    ds_var = next((item for item in variables if item.get("name") == "DS_PROMETHEUS"), None)
    if not ds_var:
        errors.append(f"{path}: missing DS_PROMETHEUS datasource variable")
    else:
        if ds_var.get("type") != "datasource" or ds_var.get("query") != "prometheus":
            errors.append(f"{path}: DS_PROMETHEUS must be a prometheus datasource variable")
        current = ds_var.get("current", {})
        if current.get("value") != "prometheus":
            errors.append(f"{path}: DS_PROMETHEUS current value must be prometheus")

    for panel_path, panel in iter_panels(data.get("panels", [])):
        for target in panel.get("targets") or []:
            expr = target.get("expr")
            if not expr:
                continue
            datasource = panel_datasource(panel, target, data)
            if not is_prometheus_datasource(datasource):
                errors.append(f"{path}: {panel_path}: target missing ${'{'}DS_PROMETHEUS{'}'} datasource")
            for metric in sorted(extract_promql_metrics(expr)):
                if not metric_known(metric, source_metrics):
                    errors.append(f"{path}: {panel_path}: unknown metric {metric!r} in {expr!r}")
    return errors


def validate_dashboards(source_metrics: set[str]) -> list[str]:
    errors: list[str] = []
    seen_uids: dict[str, Path] = {}
    for path in sorted(DASHBOARDS.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        uid = data.get("uid")
        if uid in seen_uids:
            errors.append(f"{path}: duplicate uid {uid!r}; first seen in {seen_uids[uid]}")
        elif uid:
            seen_uids[uid] = path
        errors.extend(validate_dashboard(path, source_metrics))
    if not seen_uids:
        errors.append("no dashboards found")
    return errors


def validate_alerts(source_metrics: set[str]) -> list[str]:
    path = GRAFANA / "alerts" / "rules.yml"
    text = path.read_text(encoding="utf-8")
    errors: list[str] = []
    expressions = extract_alert_expressions(text)
    if not expressions:
        errors.append(f"{path}: no alert expressions found")
    names = re.findall(r"^\s*-\s*alert:\s*([A-Za-z0-9_:-]+)\s*$", text, re.M)
    if len(names) != len(set(names)):
        errors.append(f"{path}: duplicate alert names present")
    for expr in expressions:
        for metric in sorted(extract_promql_metrics(expr)):
            if not metric_known(metric, source_metrics):
                errors.append(f"{path}: unknown metric {metric!r} in alert expression {expr!r}")
    return errors


def validate_text_contracts() -> list[str]:
    errors: list[str] = []
    for path, tokens in FORBIDDEN_TEXT.items():
        text = path.read_text(encoding="utf-8")
        for token in tokens:
            if token in text:
                errors.append(f"{path}: stale token still present: {token!r}")
    for path, tokens in REQUIRED_TEXT.items():
        text = path.read_text(encoding="utf-8")
        for token in tokens:
            if token not in text:
                errors.append(f"{path}: required token missing: {token!r}")
    return errors


def main() -> int:
    source_metrics = load_source_metric_names()
    if not source_metrics:
        fail("no source metric names discovered")
    errors = []
    errors.extend(validate_dashboards(source_metrics))
    errors.extend(validate_alerts(source_metrics))
    errors.extend(validate_text_contracts())
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(
        "GRAFANA_METADATA_PASS "
        f"dashboards={len(list(DASHBOARDS.glob('*.json')))} "
        f"source_metrics={len(source_metrics)}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
