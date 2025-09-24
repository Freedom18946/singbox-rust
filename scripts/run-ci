#!/usr/bin/env bash
set -euo pipefail
# Safe prom wrapper (no-op if prom.sh/args missing)
SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/lib/prom_wrap.sh"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN="${BIN:-${ROOT}/target/debug/singbox-rust}"
REPORT_DIR="${REPORT_DIR:-${ROOT}/target/ci}"
mkdir -p "${REPORT_DIR}"

log() { echo "[$(date +%H:%M:%S)] $*"; }

# -------- Phase A: 无指标冒烟（不触 /metrics） --------
log "Phase A: smoke (no metrics)"
cargo build -q --bin singbox-rust
NEED_METRICS=0 SB_VALIDATE_LABELS=0 SB_GATES_ONLY=1 \
  "${ROOT}/scripts/run-scenarios" \
  --scenes "check_good,check_bad,http_405,socks5_tcp_connect" \
  --report "${REPORT_DIR}/A_smoke.json"

# -------- Phase B: 指标 + label 校验（loose） --------
log "Phase B: metrics + label validation (loose)"
cargo build -q --features metrics --bin singbox-rust
SB_SCENARIO_GATES="${SB_SCENARIO_GATES:-loose}" \
NEED_METRICS=1 SB_METRICS_ADDR="${SB_METRICS_ADDR:-127.0.0.1:9090}" SB_GATES_ONLY=1 \
SB_VALIDATE_LABELS=1 SB_LABEL_GATES="${SB_LABEL_GATES:-loose}" \
  "${ROOT}/scripts/run-scenarios" \
  --scenes "${SCENES_B:-http_405,socks5_udp_direct,dns_udp}" \
  --report "${REPORT_DIR}/B_metrics.json"

# -------- Phase C: 扩展内链路（可选全开） --------
if [[ "${SB_CI_FULL:-0}" == "1" ]]; then
  log "Phase C: full internal link guardrails"
  export SB_E2E_DNS_DOT="${SB_E2E_DNS_DOT:-1}"
  export SB_E2E_DNS_DOH="${SB_E2E_DNS_DOH:-1}"
  export SB_E2E_UP_CONF="${SB_E2E_UP_CONF:-1}"
  export SB_E2E_P2_TREND="${SB_E2E_P2_TREND:-1}"
  export SB_E2E_P2_RECOVERY="${SB_E2E_P2_RECOVERY:-1}"
  export SB_E2E_UDP_STABILITY="${SB_E2E_UDP_STABILITY:-1}"
  export SB_E2E_CHECK_UNKNOWN="${SB_E2E_CHECK_UNKNOWN:-1}"
  export SB_E2E_CHECK_REF_MISS="${SB_E2E_CHECK_REF_MISS:-1}"
  export UDP_STAB_SEC="${UDP_STAB_SEC:-60}"
  SB_SCENARIO_GATES="${SB_SCENARIO_GATES:-loose}" \
  NEED_METRICS=1 SB_METRICS_ADDR="${SB_METRICS_ADDR:-127.0.0.1:9090}" SB_GATES_ONLY=1 \
  SB_VALIDATE_LABELS=1 SB_LABEL_GATES="${SB_LABEL_GATES:-loose}" \
    "${ROOT}/scripts/run-scenarios" \
    --scenes "${SCENES_C:-dns_dot_internal,dns_doh_internal,socks5_udp_upstream_conf,selector_p2_trend,selector_p2_recovery,udp_upstream_stability,check_unknown,check_ref_missing}" \
    --duration "${DURATION_SEC:-0}" \
    --report "${REPORT_DIR}/C_full.json"
fi

# -------- 汇总 → JUnit --------
log "Summarize → JUnit"
"${ROOT}/scripts/lib/junit.sh" "${REPORT_DIR}" > "${REPORT_DIR}/junit.xml"

# use safe wrapper (no-op if not available / args missing)
prom_safe prom_dump_by_prefix "${SB_METRICS_ADDR:-127.0.0.1:9090}" "proxy_select_params" >/dev/null || true

log "Done. Reports in ${REPORT_DIR}"