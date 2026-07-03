#!/usr/bin/env bash
# P1313-12: GUI.for SingBox 1.25.1 local contract probe.
#
# This intentionally avoids real Wails/desktop automation. It checks the local
# kernel process/log contract plus the GUI-side system proxy endpoint shape using
# tracked GUI 1.25.1 fixtures.
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
KERNEL="${KERNEL:-$REPO/target/debug/app}"
WORK="${WORK:-/tmp/p1313_12_gui1251}"
MIXED_PORT="${MIXED_PORT:-20122}"
CLASH_PORT="${CLASH_PORT:-20123}"
ORIGIN_PORT="${ORIGIN_PORT:-18080}"
SECRET="${SECRET:-$(python3 - <<'PY'
import secrets

print("p1313-12-" + secrets.token_urlsafe(18))
PY
)}"
PASS=0
FAIL=0

ok() {
  echo "  [PASS] $*"
  PASS=$((PASS + 1))
}

no() {
  echo "  [FAIL] $*"
  FAIL=$((FAIL + 1))
}

cleanup() {
  if [ -n "${CORE_PID:-}" ] && kill -0 "$CORE_PID" 2>/dev/null; then
    kill -INT "$CORE_PID" 2>/dev/null || true
    sleep 1
    kill -9 "$CORE_PID" 2>/dev/null || true
  fi
  if [ -n "${ORIGIN_PID:-}" ] && kill -0 "$ORIGIN_PID" 2>/dev/null; then
    kill "$ORIGIN_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT

reset_work_dir() {
  case "$WORK" in
    /tmp/p1313_12_gui1251|/tmp/p1313_12_gui1251/*|/tmp/p1313_12_gui1251_*) ;;
    *)
      echo "refusing to reset WORK outside /tmp/p1313_12_gui1251*: $WORK"
      exit 2
      ;;
  esac

  rm -rf "$WORK"
  mkdir -p "$WORK/data/sing-box"
}

if [ ! -x "$KERNEL" ]; then
  echo "kernel not found/executable: $KERNEL"
  echo "build first: cargo build -p app --bin app --features gui_runtime"
  exit 2
fi

reset_work_dir

python3 - "$REPO" >"$WORK/system_proxy_probe.json" <<'PY'
import json
import pathlib
import sys

repo = pathlib.Path(sys.argv[1])
fixture_dir = repo / "crates/sb-config/tests/golden/gui1251"

def normalize_proxy_host(host):
    return "127.0.0.1" if not host or host in {"0.0.0.0", "::", "[::]"} else host

def endpoint(config):
    ports = {"mixed": 0, "http": 0, "socks": 0}
    by_type = {}
    for inbound in config.get("inbounds", []):
        ty = inbound.get("type")
        if ty in ports:
            ports[ty] = int(inbound.get("listen_port") or 0)
            by_type[ty] = inbound
    if ports["mixed"]:
        proxy_type = "mixed"
    elif ports["http"]:
        proxy_type = "http"
    elif ports["socks"]:
        proxy_type = "socks"
    else:
        return None

    inbound = by_type[proxy_type]
    users = inbound.get("users") or []
    user = users[0] if users else {}
    return {
        "schema": "socks5" if proxy_type == "socks" else "http",
        "host": normalize_proxy_host(str(inbound.get("listen") or "").strip()),
        "port": ports[proxy_type],
        "username": user.get("username") or "",
        "password": user.get("password") or "",
        "proxyType": proxy_type,
    }

cases = {
    "mixed_auth.json": {
        "schema": "http",
        "host": "127.0.0.1",
        "port": 20122,
        "username": "carol",
        "password": "mi:xed",
        "proxyType": "mixed",
    },
    "http_only_auth.json": {
        "schema": "http",
        "host": "127.0.0.1",
        "port": 20121,
        "username": "alice",
        "password": "pa:ss",
        "proxyType": "http",
    },
    "socks_only_auth.json": {
        "schema": "socks5",
        "host": "127.0.0.1",
        "port": 20120,
        "username": "bob",
        "password": "so:cks",
        "proxyType": "socks",
    },
    "composite_route_dns_profile.json": {
        "schema": "http",
        "host": "127.0.0.1",
        "port": 20122,
        "username": "gui",
        "password": "pa:ss",
        "proxyType": "mixed",
    },
}

observed = {}
for name, expected in cases.items():
    config = json.loads((fixture_dir / name).read_text())
    actual = endpoint(config)
    observed[name] = actual
    if actual != expected:
        raise SystemExit(f"{name}: expected {expected}, got {actual}")

print(json.dumps(observed, indent=2, sort_keys=True))
PY
if [ $? -eq 0 ]; then
  ok "GUI 1.25.1 system proxy endpoint shape matches fixture expectations"
else
  no "system proxy endpoint shape probe failed"
fi

cat >"$WORK/data/sing-box/config.json" <<EOF
{
  "log": { "level": "info", "timestamp": false },
  "experimental": {
    "clash_api": {
      "external_controller": "127.0.0.1:$CLASH_PORT",
      "secret": "$SECRET",
      "default_mode": "rule"
    }
  },
  "inbounds": [
    {
      "type": "mixed",
      "tag": "mixed-in",
      "listen": "127.0.0.1",
      "listen_port": $MIXED_PORT
    }
  ],
  "outbounds": [
    { "type": "selector", "tag": "select", "outbounds": ["direct"], "default": "direct" },
    { "type": "direct", "tag": "direct" },
    { "type": "block", "tag": "block" }
  ],
  "route": {
    "rules": [
      { "clash_mode": "direct", "action": "route", "outbound": "direct" }
    ],
    "final": "select"
  }
}
EOF

ln -sf "$KERNEL" "$WORK/data/sing-box/sing-box"
ABS="$WORK/data/sing-box"

python3 -m http.server "$ORIGIN_PORT" --bind 127.0.0.1 >"$WORK/origin.log" 2>&1 &
ORIGIN_PID=$!
sleep 1

wait_started() {
  log_file="$1"
  i=0
  while [ "$i" -lt 50 ]; do
    grep -q "sing-box started" "$log_file" && return 0
    sleep 0.2
    i=$((i + 1))
  done
  return 1
}

wait_port_closed() {
  port="$1"
  i=0
  while [ "$i" -lt 40 ]; do
    if ! nc -z 127.0.0.1 "$port" 2>/dev/null; then
      return 0
    fi
    sleep 0.25
    i=$((i + 1))
  done
  return 1
}

echo "== GUI-style launch =="
"$ABS/sing-box" run --disable-color -c "$ABS/config.json" -D "$ABS" >"$WORK/core.log" 2>&1 &
CORE_PID=$!

if wait_started "$WORK/core.log"; then
  ok "startup log contains 'sing-box started'"
else
  no "startup log did not contain 'sing-box started'"
fi

if [ ! -e "$ABS/sing-box.pid" ]; then
  ok "kernel launch does not depend on GUI-owned PID file"
else
  no "kernel unexpectedly wrote GUI-owned PID file"
fi

if nc -z 127.0.0.1 "$MIXED_PORT" 2>/dev/null; then
  ok "mixed inbound bound on $MIXED_PORT"
else
  no "mixed inbound did not bind on $MIXED_PORT"
fi

if nc -z 127.0.0.1 "$CLASH_PORT" 2>/dev/null; then
  ok "Clash API bound on $CLASH_PORT"
else
  no "Clash API did not bind on $CLASH_PORT"
fi

echo "== Clash API and proxy path =="
unauth="$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$CLASH_PORT/configs" --max-time 5)"
if [ "$unauth" = "401" ]; then
  ok "Clash API rejects missing Bearer token"
else
  no "Clash API missing-token status $unauth, expected 401"
fi

cfg="$(curl -s -H "Authorization: Bearer $SECRET" "http://127.0.0.1:$CLASH_PORT/configs" --max-time 5)"
case "$cfg" in
  *mixed-port*) ok "/configs returns GUI-readable config JSON" ;;
  *) no "/configs did not return expected JSON" ;;
esac

status="$(curl -s -o /dev/null -w "%{http_code}" -x "http://127.0.0.1:$MIXED_PORT" "http://127.0.0.1:$ORIGIN_PORT/" --max-time 5)"
if [ "$status" = "200" ]; then
  ok "mixed HTTP proxy path reaches local origin"
else
  no "mixed HTTP proxy path status $status, expected 200"
fi

echo "== Stop =="
kill -INT "$CORE_PID" 2>/dev/null || true
if wait_port_closed "$MIXED_PORT"; then
  ok "mixed inbound port released after SIGINT"
else
  no "mixed inbound port still bound after SIGINT"
fi
CORE_PID=

echo
echo "== summary: PASS=$PASS FAIL=$FAIL =="
if [ "$FAIL" -eq 0 ]; then
  echo "P1313-12 GUI 1.25.1 CONTRACT PROBE: PASS"
else
  echo "P1313-12 GUI 1.25.1 CONTRACT PROBE: FAIL"
fi
exit "$FAIL"
