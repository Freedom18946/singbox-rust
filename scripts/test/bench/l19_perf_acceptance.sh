#!/usr/bin/env bash
if [[ "${BASH_VERSINFO[0]:-0}" -lt 4 ]]; then
    _script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if _bash4="$("$_script_dir/../../lib/bash4_detect.sh" 2>/dev/null)"; then
        exec "$_bash4" "$0" "$@"
    fi
    echo "ERROR: bash >= 4 is required" >&2
    exit 2
fi

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
cd "$PROJECT_ROOT"

RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
OUT_ROOT="$PROJECT_ROOT/reports/performance/l19"
RUN_DIR=""
REPORT_JSON=""
LAYER="all"
QUICK=0
DRY_RUN=0
STRICT=0

usage() {
    cat <<'EOF'
Usage: scripts/test/bench/l19_perf_acceptance.sh [options]

L19.4.3 performance acceptance entrypoint:
- Layer A: baseline
- Layer B: router_api
- Layer C: parity

Options:
  --layer <baseline|router_api|parity|all>  Select layer (default: all)
  --out-root <dir>                           Output root directory
  --run-id <id>                              Override run id
  --quick                                    Reduce sample sizes / rounds
  --dry-run                                  Print commands only
  --strict                                   Treat env-limited as fail
  -h, --help                                 Show this help

Exit codes:
  0  PASS / PASS-ENV-LIMITED / DRY-RUN
  1  FAIL
  2  Invalid arguments
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --layer)
            LAYER="${2:-}"
            shift 2
            ;;
        --out-root)
            OUT_ROOT="${2:-}"
            shift 2
            ;;
        --run-id)
            RUN_ID="${2:-}"
            shift 2
            ;;
        --quick)
            QUICK=1
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        --strict)
            STRICT=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "ERROR: unknown argument: $1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

case "$LAYER" in
    baseline|router_api|parity|all) ;;
    *)
        echo "ERROR: --layer must be one of baseline|router_api|parity|all" >&2
        exit 2
        ;;
esac

RUN_DIR="$OUT_ROOT/$RUN_ID"
REPORT_JSON="$RUN_DIR/l19_perf_acceptance.json"
LAYER_JSON_DIR="$RUN_DIR/layers"
ARTIFACT_DIR="$RUN_DIR/artifacts"
LOG_DIR="$RUN_DIR/logs"

mkdir -p "$LAYER_JSON_DIR" "$ARTIFACT_DIR" "$LOG_DIR"

log() {
    echo "[l19-perf] $*"
}

run_cmd() {
    local cmd="$1"
    local log_file="$2"
    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf '[dry-run] %s\n' "$cmd" >>"$log_file"
        log "dry-run: $cmd"
        return 0
    fi

    set +e
    printf '$ %s\n' "$cmd" >>"$log_file"
    bash -lc "$cmd" >>"$log_file" 2>&1
    local rc=$?
    set -e
    return "$rc"
}

snapshot_artifact() {
    local layer="$1"
    local key="$2"
    local src="$3"
    local artifact_index_file="$4"

    if [[ -f "$src" ]]; then
        local dest="$ARTIFACT_DIR/${layer}_${key}_$(basename "$src")"
        cp "$src" "$dest"
        printf '%s=%s\n' "$key" "$dest" >>"$artifact_index_file"
    else
        printf '%s=\n' "$key" >>"$artifact_index_file"
    fi
}

emit_layer_json() {
    local layer="$1"
    local status="$2"
    local reason="$3"
    local layer_log="$4"
    local cmd_index_file="$5"
    local artifact_index_file="$6"
    local out_json="$LAYER_JSON_DIR/${layer}.json"

    python3 - "$out_json" "$layer" "$status" "$reason" "$layer_log" "$cmd_index_file" "$artifact_index_file" <<'PY'
import json
import os
import sys

out_json, layer, status, reason, layer_log, cmd_index_file, artifact_index_file = sys.argv[1:]

commands = []
if os.path.exists(cmd_index_file):
    with open(cmd_index_file, "r", encoding="utf-8") as f:
        commands = [line.strip() for line in f if line.strip()]

artifacts = {}
if os.path.exists(artifact_index_file):
    with open(artifact_index_file, "r", encoding="utf-8") as f:
        for raw in f:
            raw = raw.rstrip("\n")
            if not raw:
                continue
            if "=" in raw:
                key, value = raw.split("=", 1)
                artifacts[key] = value

payload = {
    "layer": layer,
    "status": status,
    "reason": reason,
    "log_file": layer_log,
    "commands": commands,
    "artifacts": artifacts,
}

with open(out_json, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2, ensure_ascii=False)
    f.write("\n")
PY
}

write_perf_percentiles() {
    local layer="$1"
    local perf_report_json="$2"
    local out_json="$3"
    local layer_work_dir="$4"

    python3 - "$layer" "$perf_report_json" "$out_json" "$layer_work_dir" <<'PY'
import json
import math
import os
import sys
from datetime import datetime, timezone

layer, perf_report_json, out_json, layer_work_dir = sys.argv[1:]

def read_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def read_samples(path):
    vals = []
    if not os.path.exists(path):
        return vals
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            raw = raw.strip()
            if not raw:
                continue
            try:
                vals.append(float(raw))
            except ValueError:
                continue
    return vals

def percentile(values, q):
    if not values:
        return None
    values = sorted(values)
    idx = max(0, min(len(values) - 1, int(math.ceil(q * len(values))) - 1))
    return round(values[idx] * 1000.0, 6)  # seconds -> ms

payload = {
    "schema_version": "1.0.0",
    "layer": layer,
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "latency_ms": {
        "cold": {"rust": {}, "go": {}},
        "warm": {"rust": {}, "go": {}},
        "all": {"rust": {}, "go": {}},
    },
    "conn_rss_delta_bytes_per_conn": {
        "connections_100": {"rust": None, "go": None},
        "connections_1000": {"rust": None, "go": None},
    },
    "source": {
        "perf_gate_json": perf_report_json,
        "memory_comparison_json": "",
    },
    "note": "",
}

if not os.path.exists(perf_report_json):
    payload["note"] = "perf_gate report missing; percentiles unavailable"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
        f.write("\n")
    sys.exit(0)

report = read_json(perf_report_json)
round_dirs = report.get("inputs", {}).get("round_dirs", [])
if not round_dirs:
    payload["note"] = "round_dirs missing in perf_gate report"
else:
    cold_rounds = round_dirs[:1]
    warm_rounds = round_dirs[1:] if len(round_dirs) > 1 else round_dirs[:1]

    def collect(core, rounds):
        combined = []
        for rd in rounds:
            combined.extend(read_samples(os.path.join(rd, f"{core}_latency_samples.txt")))
        return combined

    for core in ("rust", "go"):
        cold_vals = collect(core, cold_rounds)
        warm_vals = collect(core, warm_rounds)
        all_vals = collect(core, round_dirs)
        payload["latency_ms"]["cold"][core] = {
            "p50": percentile(cold_vals, 0.50),
            "p95": percentile(cold_vals, 0.95),
            "p99": percentile(cold_vals, 0.99),
            "sample_size": len(cold_vals),
        }
        payload["latency_ms"]["warm"][core] = {
            "p50": percentile(warm_vals, 0.50),
            "p95": percentile(warm_vals, 0.95),
            "p99": percentile(warm_vals, 0.99),
            "sample_size": len(warm_vals),
        }
        payload["latency_ms"]["all"][core] = {
            "p50": percentile(all_vals, 0.50),
            "p95": percentile(all_vals, 0.95),
            "p99": percentile(all_vals, 0.99),
            "sample_size": len(all_vals),
        }

memory_path = report.get("inputs", {}).get("memory_report") or os.path.join(layer_work_dir, "memory_comparison.json")
payload["source"]["memory_comparison_json"] = memory_path
if os.path.exists(memory_path):
    mem = read_json(memory_path)
    for core in ("rust", "go"):
        core_data = mem.get(core, {}).get("measurements", {})
        c100 = core_data.get("connections_100", {})
        c1000 = core_data.get("connections_1000", {})
        try:
            delta100 = float(c100.get("delta_over_idle_kb", 0.0))
            payload["conn_rss_delta_bytes_per_conn"]["connections_100"][core] = round(delta100 * 1024.0 / 100.0, 3)
        except Exception:
            payload["conn_rss_delta_bytes_per_conn"]["connections_100"][core] = None
        try:
            delta1000 = float(c1000.get("delta_over_idle_kb", 0.0))
            payload["conn_rss_delta_bytes_per_conn"]["connections_1000"][core] = round(delta1000 * 1024.0 / 1000.0, 3)
        except Exception:
            payload["conn_rss_delta_bytes_per_conn"]["connections_1000"][core] = None
else:
    if payload["note"]:
        payload["note"] += "; memory_comparison missing"
    else:
        payload["note"] = "memory_comparison missing"

with open(out_json, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2, ensure_ascii=False)
    f.write("\n")
PY
}

run_baseline_layer() {
    local layer="baseline"
    local layer_log="$LOG_DIR/${layer}.log"
    : >"$layer_log"
    local cmd_index_file="$RUN_DIR/${layer}_commands.txt"
    local artifact_index_file="$RUN_DIR/${layer}_artifacts.txt"
    : >"$cmd_index_file"
    : >"$artifact_index_file"

    local status="PASS"
    local reason="all commands succeeded"

    local cmd1="bash scripts/test/bench/run.sh"
    printf '%s\n' "$cmd1" >>"$cmd_index_file"

    if ! run_cmd "$cmd1" "$layer_log"; then
        status="ENV_LIMITED"
        reason="baseline step failed: run.sh"
    fi

    if [[ "$DRY_RUN" -eq 1 ]]; then
        status="DRY_RUN"
        reason="commands not executed"
    fi
    if [[ "$STRICT" -eq 1 && "$status" == "ENV_LIMITED" ]]; then
        status="FAIL"
    fi

    snapshot_artifact "$layer" "bench_summary" "$PROJECT_ROOT/target/bench/summary.csv" "$artifact_index_file"
    emit_layer_json "$layer" "$status" "$reason" "$layer_log" "$cmd_index_file" "$artifact_index_file"
}

run_perf_layer() {
    local layer="$1"
    local rust_features="$2"
    local layer_log="$LOG_DIR/${layer}.log"
    : >"$layer_log"
    local cmd_index_file="$RUN_DIR/${layer}_commands.txt"
    local artifact_index_file="$RUN_DIR/${layer}_artifacts.txt"
    : >"$cmd_index_file"
    : >"$artifact_index_file"

    local perf_report_json="$RUN_DIR/${layer}_perf_gate.json"
    local perf_lock_json="$RUN_DIR/${layer}_perf_gate.lock.json"
    local layer_work_dir="$RUN_DIR/${layer}_work"
    local percentiles_json="$RUN_DIR/${layer}_latency_percentiles.json"
    local quick_env=""

    if [[ "$QUICK" -eq 1 ]]; then
        quick_env="L18_PERF_ROUNDS=1 L18_STARTUP_SAMPLE_RUNS=3 L18_PERF_WARMUP_REQUESTS=10 L18_PERF_SAMPLE_REQUESTS=30 "
    fi

    local cmd="${quick_env}L18_RUST_BUILD_FEATURES=${rust_features} L18_PERF_GATE_REPORT=${perf_report_json} L18_PERF_GATE_LOCK=${perf_lock_json} L18_PERF_WORK_DIR=${layer_work_dir} bash scripts/l18/perf_gate.sh"
    printf '%s\n' "$cmd" >>"$cmd_index_file"

    local status="PASS"
    local reason="all commands succeeded"
    if ! run_cmd "$cmd" "$layer_log"; then
        status="ENV_LIMITED"
        reason="${layer} perf gate failed"
    fi
    if [[ "$DRY_RUN" -eq 1 ]]; then
        status="DRY_RUN"
        reason="commands not executed"
    fi
    if [[ "$STRICT" -eq 1 && "$status" == "ENV_LIMITED" ]]; then
        status="FAIL"
    fi

    write_perf_percentiles "$layer" "$perf_report_json" "$percentiles_json" "$layer_work_dir"

    snapshot_artifact "$layer" "perf_gate" "$perf_report_json" "$artifact_index_file"
    snapshot_artifact "$layer" "perf_lock" "$perf_lock_json" "$artifact_index_file"
    snapshot_artifact "$layer" "memory_comparison" "$layer_work_dir/memory_comparison.json" "$artifact_index_file"
    snapshot_artifact "$layer" "latency_percentiles" "$percentiles_json" "$artifact_index_file"
    emit_layer_json "$layer" "$status" "$reason" "$layer_log" "$cmd_index_file" "$artifact_index_file"
}

layers=()
if [[ "$LAYER" == "all" ]]; then
    layers=(baseline router_api parity)
else
    layers=("$LAYER")
fi

log "run_id=${RUN_ID} layer=${LAYER} quick=${QUICK} dry_run=${DRY_RUN} strict=${STRICT}"

for layer in "${layers[@]}"; do
    case "$layer" in
        baseline)
            run_baseline_layer
            ;;
        router_api)
            run_perf_layer "router_api" "acceptance"
            ;;
        parity)
            run_perf_layer "parity" "parity"
            ;;
        *)
            echo "ERROR: unknown internal layer $layer" >&2
            exit 2
            ;;
    esac
done

python3 - "$REPORT_JSON" "$RUN_ID" "$RUN_DIR" "$LAYER_JSON_DIR" "${layers[*]}" <<'PY'
import json
import os
import sys
from datetime import datetime, timezone

report_json, run_id, run_dir, layer_json_dir, layer_csv = sys.argv[1:]
layers = [x for x in layer_csv.split(" ") if x]

payload_layers = []
status_set = []
for layer in layers:
    path = os.path.join(layer_json_dir, f"{layer}.json")
    if not os.path.exists(path):
        payload_layers.append(
            {
                "layer": layer,
                "status": "FAIL",
                "reason": "layer report missing",
                "commands": [],
                "artifacts": {},
            }
        )
        status_set.append("FAIL")
        continue
    with open(path, "r", encoding="utf-8") as f:
        layer_payload = json.load(f)
    payload_layers.append(layer_payload)
    status_set.append(layer_payload.get("status", "FAIL"))

overall = "PASS"
if any(s == "FAIL" for s in status_set):
    overall = "FAIL"
elif any(s in {"ENV_LIMITED", "DRY_RUN"} for s in status_set):
    overall = "PASS-ENV-LIMITED"

payload = {
    "schema_version": "1.0.0",
    "profile": "l19.4.3-performance-acceptance",
    "run_id": run_id,
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "overall": overall,
    "run_dir": run_dir,
    "method_contract": {
        "layers": ["baseline", "router_api", "parity"],
        "latency_percentiles": ["p50", "p95", "p99"],
        "cold_warm_definition": {
            "cold": "round_01",
            "warm": "round_02..round_N (fallback round_01 if only one round)",
        },
        "platform_scope": ["Darwin-arm64", "Linux-x86_64"],
        "feature_sets": {
            "baseline": "sb-benches benchmark suite",
            "router_api": "scripts/l18/perf_gate.sh with L18_RUST_BUILD_FEATURES=acceptance",
            "parity": "scripts/l18/perf_gate.sh with L18_RUST_BUILD_FEATURES=parity",
        },
    },
    "layers": payload_layers,
}

with open(report_json, "w", encoding="utf-8") as f:
    json.dump(payload, f, indent=2, ensure_ascii=False)
    f.write("\n")
PY

mkdir -p "$OUT_ROOT"
cp "$REPORT_JSON" "$OUT_ROOT/latest.json"

log "report: $REPORT_JSON"
log "latest: $OUT_ROOT/latest.json"

if python3 - "$REPORT_JSON" <<'PY'
import json
import sys

with open(sys.argv[1], "r", encoding="utf-8") as f:
    payload = json.load(f)
sys.exit(1 if payload.get("overall") == "FAIL" else 0)
PY
then
    exit 0
fi

exit 1
