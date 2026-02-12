#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  gui_smoke_test.sh \
    --gui-root <path> \
    --kernel-bin <path> \
    --config <path> \
    --api-url <url> \
    --report <path> \
    --artifacts-dir <path>
EOF
}

GUI_ROOT=""
KERNEL_BIN=""
CONFIG_PATH=""
API_URL=""
REPORT_PATH=""
ARTIFACTS_DIR=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --gui-root) GUI_ROOT="$2"; shift 2 ;;
    --kernel-bin) KERNEL_BIN="$2"; shift 2 ;;
    --config) CONFIG_PATH="$2"; shift 2 ;;
    --api-url) API_URL="$2"; shift 2 ;;
    --report) REPORT_PATH="$2"; shift 2 ;;
    --artifacts-dir) ARTIFACTS_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

if [[ -z "$GUI_ROOT" || -z "$KERNEL_BIN" || -z "$CONFIG_PATH" || -z "$API_URL" || -z "$REPORT_PATH" || -z "$ARTIFACTS_DIR" ]]; then
  usage
  exit 2
fi

[[ -d "$GUI_ROOT" ]] || { echo "gui root not found: $GUI_ROOT" >&2; exit 1; }
[[ -x "$KERNEL_BIN" ]] || { echo "kernel bin not executable: $KERNEL_BIN" >&2; exit 1; }
[[ -f "$CONFIG_PATH" ]] || { echo "config not found: $CONFIG_PATH" >&2; exit 1; }

mkdir -p "$ARTIFACTS_DIR"
mkdir -p "$(dirname "$REPORT_PATH")"

KERNEL_LOG="$ARTIFACTS_DIR/kernel.stdout.log"
PROBES_JSON="$ARTIFACTS_DIR/http_probes.json"
MANUAL_NOTE="$ARTIFACTS_DIR/manual_notes.md"

"$KERNEL_BIN" run --config "$CONFIG_PATH" >"$KERNEL_LOG" 2>&1 &
KERNEL_PID=$!

cleanup() {
  if kill -0 "$KERNEL_PID" >/dev/null 2>&1; then
    kill "$KERNEL_PID" >/dev/null 2>&1 || true
    wait "$KERNEL_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

health_code="000"
for _ in $(seq 1 60); do
  health_code="$(curl -sS -o /dev/null -w '%{http_code}' "$API_URL/services/health" || echo 000)"
  if [[ "$health_code" == "200" ]]; then
    break
  fi
  sleep 1
done

probe_code() {
  local path="$1"
  curl -sS -o /dev/null -w '%{http_code}' "$API_URL$path" || echo 000
}

proxies_code="$(probe_code /proxies)"
connections_code="$(probe_code /connections)"
providers_code="$(probe_code /providers/proxies)"

cat > "$PROBES_JSON" <<EOF
{
  "api_url": "$API_URL",
  "health": $health_code,
  "proxies": $proxies_code,
  "connections": $connections_code,
  "providers_proxies": $providers_code,
  "kernel_pid": $KERNEL_PID
}
EOF

cat > "$MANUAL_NOTE" <<'EOF'
# GUI 手工检查记录

- [ ] GUI 启动并加载配置
- [ ] Proxy 切换后 UI 状态更新
- [ ] 订阅导入成功并更新节点
- [ ] Connections 面板显示活跃连接
- [ ] Logs 面板持续刷新

备注：
EOF

cat > "$REPORT_PATH" <<EOF
# GUI Integration Smoke Report

- Date: $(date -u +'%Y-%m-%dT%H:%M:%SZ')
- GUI Root: \`$GUI_ROOT\`
- Kernel Bin: \`$KERNEL_BIN\`
- Config: \`$CONFIG_PATH\`
- API URL: \`$API_URL\`

## Auto Probes

| Check | Result | Pass Criteria |
|---|---:|---|
| \`GET /services/health\`
 | $health_code | 200 |
| \`GET /proxies\`
 | $proxies_code | 200/401/404* |
| \`GET /connections\`
 | $connections_code | 200/401/404* |
| \`GET /providers/proxies\`
 | $providers_code | 200/401/404* |

\* 401/404 may be expected depending on auth and feature gating; see artifacts.

## Manual GUI Checklist

See \`$MANUAL_NOTE\`
 and fill in operator observations.

## Artifacts

- Probe JSON: \`$PROBES_JSON\`
- Kernel log: \`$KERNEL_LOG\`
- Manual notes: \`$MANUAL_NOTE\`
EOF

echo "report generated: $REPORT_PATH"
