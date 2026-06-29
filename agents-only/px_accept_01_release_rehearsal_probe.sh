#!/usr/bin/env bash
# PX-ACCEPT-01: local drop-in release rehearsal probe.
#
# This is intentionally local-only: no Wails automation, no privileged TUN,
# no public DNS or remote rule-set dependency. It turns the GUI 1.25.1
# composite fixture into a temporary runtime config and drives the real app
# binary through startup, Clash API, proxy, DNS, selector/cache, reload, and
# post-reload admin state checks.
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
KERNEL="${KERNEL:-$REPO/target/debug/app}"
WORK="${WORK:-/tmp/px_accept_01_release_rehearsal}"
KEEP_WORK="${KEEP_WORK:-1}"
SECRET="${SECRET:-px-accept-secret}"
ADMIN_TOKEN="${ADMIN_TOKEN:-px-accept-admin-token}"
FIXTURE="$REPO/crates/sb-config/tests/golden/gui1251/composite_route_dns_profile.json"
RESULTS="$WORK/results.tsv"
SUMMARY="$WORK/summary.json"
PASS=0
FAIL=0
WARN=0

CORE_PID=""
ORIGIN_PID=""
SLOW_CURL_PID=""

record() {
  status="$1"
  name="$2"
  detail="$3"
  printf '%s\t%s\t%s\n' "$status" "$name" "$detail" >>"$RESULTS"
}

ok() {
  echo "  [PASS] $*"
  PASS=$((PASS + 1))
  record PASS "$1" "${2:-}"
}

no() {
  echo "  [FAIL] $*"
  FAIL=$((FAIL + 1))
  record FAIL "$1" "${2:-}"
}

warn() {
  echo "  [WARN] $*"
  WARN=$((WARN + 1))
  record WARN "$1" "${2:-}"
}

cleanup_processes() {
  if [ -n "${SLOW_CURL_PID:-}" ] && kill -0 "$SLOW_CURL_PID" 2>/dev/null; then
    kill "$SLOW_CURL_PID" 2>/dev/null || true
  fi
  if [ -n "${CORE_PID:-}" ] && kill -0 "$CORE_PID" 2>/dev/null; then
    kill -INT "$CORE_PID" 2>/dev/null || true
    sleep 1
    kill -9 "$CORE_PID" 2>/dev/null || true
  fi
  if [ -n "${ORIGIN_PID:-}" ] && kill -0 "$ORIGIN_PID" 2>/dev/null; then
    kill "$ORIGIN_PID" 2>/dev/null || true
  fi
}
trap cleanup_processes EXIT

write_summary() {
  python3 - "$RESULTS" "$SUMMARY" "$WORK" "$KERNEL" "$FIXTURE" "$PASS" "$FAIL" "$WARN" "$REPO" <<'PY'
import json
import pathlib
import subprocess
import sys
from datetime import datetime, timezone

results_path = pathlib.Path(sys.argv[1])
summary_path = pathlib.Path(sys.argv[2])
work = pathlib.Path(sys.argv[3])
kernel = pathlib.Path(sys.argv[4])
fixture = pathlib.Path(sys.argv[5])
pass_count = int(sys.argv[6])
fail_count = int(sys.argv[7])
warn_count = int(sys.argv[8])
repo = pathlib.Path(sys.argv[9])

steps = []
if results_path.exists():
    for line in results_path.read_text().splitlines():
        status, name, detail = (line.split("\t", 2) + ["", ""])[:3]
        steps.append({"status": status, "name": name, "detail": detail})

def git(args):
    try:
        return subprocess.check_output(["git", *args], cwd=repo, text=True).strip()
    except Exception:
        return ""

summary = {
    "schema": "px-accept-01.release_rehearsal.v1",
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "repo": str(repo),
    "head": git(["rev-parse", "HEAD"]),
    "branch": git(["rev-parse", "--abbrev-ref", "HEAD"]),
    "profile": "gui_runtime",
    "kernel": str(kernel),
    "fixture": str(fixture),
    "work": str(work),
    "pass": pass_count,
    "fail": fail_count,
    "warn": warn_count,
    "ok": fail_count == 0,
    "steps": steps,
}
summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
PY
}

finish() {
  cleanup_processes
  write_summary
  echo
  echo "== summary: PASS=$PASS FAIL=$FAIL WARN=$WARN =="
  echo "summary: $SUMMARY"
  if [ "$KEEP_WORK" = "1" ] || [ "$FAIL" -ne 0 ]; then
    echo "workdir: $WORK"
  fi
  if [ "$FAIL" -eq 0 ]; then
    echo "PX-ACCEPT-01 RELEASE REHEARSAL: PASS"
    exit 0
  fi
  echo "PX-ACCEPT-01 RELEASE REHEARSAL: FAIL"
  exit 1
}

require_tool() {
  if command -v "$1" >/dev/null 2>&1; then
    return 0
  fi
  echo "required tool not found: $1"
  exit 2
}

wait_started() {
  log_file="$1"
  i=0
  while [ "$i" -lt 100 ]; do
    grep -q "sing-box started" "$log_file" && return 0
    sleep 0.2
    i=$((i + 1))
  done
  return 1
}

wait_port_open() {
  port="$1"
  i=0
  while [ "$i" -lt 80 ]; do
    nc -z 127.0.0.1 "$port" 2>/dev/null && return 0
    sleep 0.25
    i=$((i + 1))
  done
  return 1
}

wait_port_closed() {
  port="$1"
  i=0
  while [ "$i" -lt 80 ]; do
    if ! nc -z 127.0.0.1 "$port" 2>/dev/null; then
      return 0
    fi
    sleep 0.25
    i=$((i + 1))
  done
  return 1
}

http_status() {
  out="$1"
  shift
  status="$(curl -sS -o "$out" -w "%{http_code}" --max-time 8 "$@" 2>>"$WORK/curl.err" || true)"
  if [ -z "$status" ]; then
    status=000
  fi
  printf '%s' "$status"
}

json_expect() {
  name="$1"
  file="$2"
  expr="$3"
  detail="${4:-$expr}"
  if python3 - "$file" "$expr" <<'PY'
import json
import sys

path, expr = sys.argv[1], sys.argv[2]
with open(path, "r", encoding="utf-8") as fh:
    data = json.load(fh)
env = {"data": data, "isinstance": isinstance, "list": list, "dict": dict, "len": len, "any": any, "all": all, "str": str}
if not bool(eval(expr, {"__builtins__": {}, **env}, env)):
    raise SystemExit(1)
PY
  then
    ok "$name" "$detail"
  else
    no "$name" "$detail"
  fi
}

stop_core() {
  label="$1"
  if [ -n "${CORE_PID:-}" ] && kill -0 "$CORE_PID" 2>/dev/null; then
    kill -INT "$CORE_PID" 2>/dev/null || true
    wait "$CORE_PID" 2>/dev/null || true
  fi
  CORE_PID=""
  if wait_port_closed "$MIXED_PORT_1" && wait_port_closed "$MIXED_PORT_2" && wait_port_closed "$CLASH_PORT" && wait_port_closed "$ADMIN_PORT"; then
    ok "$label ports released" "mixed/admin/clash ports closed"
  else
    no "$label ports released" "one or more app ports remained open"
  fi
}

start_core() {
  label="$1"
  config="$2"
  log_file="$3"
  "$KERNEL" --disable-color -c "$config" -D "$ABS" run \
    --admin-listen "127.0.0.1:$ADMIN_PORT" \
    --admin-token "$ADMIN_TOKEN" \
    >"$log_file" 2>&1 &
  CORE_PID=$!

  if wait_started "$log_file"; then
    ok "$label startup log" "core log contains sing-box started"
  else
    no "$label startup log" "core log did not contain sing-box started"
  fi

  if wait_port_open "$CLASH_PORT"; then
    ok "$label Clash API listen" "127.0.0.1:$CLASH_PORT"
  else
    no "$label Clash API listen" "port did not open"
  fi
  if wait_port_open "$ADMIN_PORT"; then
    ok "$label core admin listen" "127.0.0.1:$ADMIN_PORT"
  else
    no "$label core admin listen" "port did not open"
  fi
}

require_tool python3
require_tool curl
require_tool nc

if [ ! -x "$KERNEL" ]; then
  echo "kernel not found/executable: $KERNEL"
  echo "build first: cargo build -p app --bin app --features gui_runtime"
  exit 2
fi

if [ ! -f "$FIXTURE" ]; then
  echo "fixture not found: $FIXTURE"
  exit 2
fi

rm -rf "$WORK"
mkdir -p "$WORK"
: >"$RESULTS"
: >"$WORK/curl.err"

python3 - "$WORK/ports.env" <<'PY'
import socket
import sys

names = [
    "MIXED_PORT_1",
    "MIXED_PORT_2",
    "CLASH_PORT",
    "ADMIN_PORT",
    "ORIGIN_PORT",
]
sockets = []
ports = []
for _ in names:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    ports.append(sock.getsockname()[1])
    sockets.append(sock)
with open(sys.argv[1], "w", encoding="utf-8") as fh:
    for name, port in zip(names, ports):
        fh.write(f"{name}={port}\n")
PY
. "$WORK/ports.env"

ABS="$WORK/data/sing-box"
mkdir -p "$ABS"

python3 - "$REPO" "$WORK" "$FIXTURE" "$SECRET" "$MIXED_PORT_1" "$MIXED_PORT_2" "$CLASH_PORT" "$ORIGIN_PORT" <<'PY'
import copy
import json
import pathlib
import sys

repo = pathlib.Path(sys.argv[1])
work = pathlib.Path(sys.argv[2])
fixture = pathlib.Path(sys.argv[3])
secret = sys.argv[4]
mixed_1 = int(sys.argv[5])
mixed_2 = int(sys.argv[6])
clash = int(sys.argv[7])
origin = int(sys.argv[8])
abs_dir = work / "data" / "sing-box"
fixture_copy = abs_dir / "gui1251_composite_source.json"
initial_path = abs_dir / "config.initial.json"
reload_path = abs_dir / "config.reload.json"

cfg = json.loads(fixture.read_text())
fixture_copy.write_text(json.dumps(cfg, indent=2, sort_keys=True) + "\n")

def runtime_config(port: int, with_block_rule: bool) -> dict:
    c = copy.deepcopy(cfg)
    c.setdefault("log", {})["level"] = "info"
    c["log"]["timestamp"] = False

    clash_api = c.setdefault("experimental", {}).setdefault("clash_api", {})
    clash_api["external_controller"] = f"127.0.0.1:{clash}"
    clash_api["secret"] = secret
    clash_api["default_mode"] = "rule"

    cache = c.setdefault("experimental", {}).setdefault("cache_file", {})
    cache["enabled"] = True
    cache["path"] = str(abs_dir / "cache.db")
    cache["cache_id"] = "px-accept-01"
    cache["store_fakeip"] = True

    for inbound in c.get("inbounds", []):
        if inbound.get("type") == "mixed":
            inbound["listen"] = "127.0.0.1"
            inbound["listen_port"] = port
            inbound["users"] = [{"username": "gui", "password": "pa:ss"}]

    for outbound in c.get("outbounds", []):
        if outbound.get("type") == "urltest":
            outbound["url"] = f"http://127.0.0.1:{origin}/generate_204"
            outbound["interval"] = "1m"

    c["route"]["rule_set"] = [
        {
            "tag": "geo-cn",
            "rules": [{"domain_suffix": ["cn"]}],
        }
    ]
    rules = []
    if with_block_rule:
        rules.append(
            {
                "domain": ["rehearsal-block.test"],
                "action": "route",
                "outbound": "Block",
            }
        )
    rules.extend([
        {"protocol": "dns", "action": "hijack-dns"},
        {
            "inbound": "mixed-in",
            "action": "sniff",
            "sniffer": "tls",
            "sniff_timeout": "300ms",
        },
    ])
    rules.extend(
        [
            {"clash_mode": "direct", "action": "route", "outbound": "Direct"},
            {"rule_set": ["geo-cn"], "action": "route", "outbound": "Block"},
        ]
    )
    c["route"]["rules"] = rules
    c["route"]["default_domain_resolver"] = {"server": "Local-DNS"}
    c["route"]["final"] = "GLOBAL"

    c["dns"] = {
        "servers": [
            {
                "tag": "Fake-IP",
                "type": "fakeip",
                "address": "fakeip",
                "inet4_range": "198.18.0.0/15",
                "inet6_range": "fc00::/18",
            },
            {
                "tag": "Local-Hosts",
                "type": "hosts",
                "address": "hosts",
                "predefined": {
                    "px-accept.local": ["203.0.113.77"],
                    "rehearsal-block.test": ["203.0.113.88"],
                },
            },
            {"tag": "Local-DNS", "type": "local", "address": "local"},
        ],
        "rules": [
            {
                "domain": ["px-accept.local", "rehearsal-block.test"],
                "action": "route",
                "server": "Local-Hosts",
            },
            {
                "domain_suffix": ["lan"],
                "action": "route",
                "server": "Local-DNS",
                "disable_cache": True,
            },
            {"ip_is_private": True, "action": "hijack-dns", "rcode": "NXDOMAIN"},
        ],
        "disable_cache": False,
        "disable_expire": False,
        "independent_cache": True,
        "final": "Local-Hosts",
    }
    return c

initial_path.write_text(json.dumps(runtime_config(mixed_1, False), indent=2, sort_keys=True) + "\n")
reload_path.write_text(json.dumps(runtime_config(mixed_2, True), indent=2, sort_keys=True) + "\n")
PY

INITIAL_CONFIG="$ABS/config.initial.json"
RELOAD_CONFIG="$ABS/config.reload.json"

cat >"$WORK/origin_server.py" <<'PY'
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import sys
import time

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/generate_204"):
            self.send_response(204)
            self.end_headers()
            return
        if self.path.startswith("/slow"):
            time.sleep(4)
        body = b"px-accept local origin\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
PY

python3 "$WORK/origin_server.py" "$ORIGIN_PORT" >"$WORK/origin.log" 2>&1 &
ORIGIN_PID=$!
if wait_port_open "$ORIGIN_PORT"; then
  ok "local origin listen" "127.0.0.1:$ORIGIN_PORT"
else
  no "local origin listen" "port did not open"
fi

echo "== DNS CLI probe =="
if "$KERNEL" --disable-color -c "$INITIAL_CONFIG" -D "$ABS" dns query px-accept.local --format json >"$WORK/dns_query.json" 2>"$WORK/dns_query.err"; then
  json_expect "DNS query uses local predefined answer" "$WORK/dns_query.json" "'203.0.113.77' in [str(x) for x in data.get('ips', [])]" "px-accept.local resolves to 203.0.113.77"
else
  no "DNS query command" "see $WORK/dns_query.err"
fi
if "$KERNEL" --disable-color -c "$INITIAL_CONFIG" -D "$ABS" dns query px-accept.local --format json --explain >"$WORK/dns_explain.json" 2>"$WORK/dns_explain.err"; then
  json_expect "DNS explain uses Local-Hosts upstream" "$WORK/dns_explain.json" "data.get('upstream') == 'Local-Hosts'" "upstream=Local-Hosts"
else
  no "DNS explain command" "see $WORK/dns_explain.err"
fi

echo "== Initial GUI-style launch =="
start_core "initial" "$INITIAL_CONFIG" "$WORK/core.initial.log"

if wait_port_open "$MIXED_PORT_1"; then
  ok "initial mixed inbound listen" "127.0.0.1:$MIXED_PORT_1"
else
  no "initial mixed inbound listen" "port did not open"
fi

status="$(http_status "$WORK/admin_health.json" -H "X-Admin-Token: $ADMIN_TOKEN" "http://127.0.0.1:$ADMIN_PORT/healthz")"
if [ "$status" = "200" ]; then
  json_expect "core admin healthz" "$WORK/admin_health.json" "data.get('ok') is True" "GET /healthz"
else
  no "core admin healthz" "status=$status"
fi

status="$(http_status "$WORK/configs.unauth.json" "http://127.0.0.1:$CLASH_PORT/configs")"
if [ "$status" = "401" ]; then
  ok "Clash API rejects missing Bearer" "GET /configs status=401"
else
  no "Clash API rejects missing Bearer" "status=$status"
fi

status="$(http_status "$WORK/configs.initial.json" -H "Authorization: Bearer $SECRET" "http://127.0.0.1:$CLASH_PORT/configs")"
if [ "$status" = "200" ]; then
  json_expect "Clash /configs GUI fields" "$WORK/configs.initial.json" "data.get('mixed-port') == $MIXED_PORT_1 and data.get('mode') in ('rule', 'direct', 'global')" "mixed-port and mode present"
else
  no "Clash /configs GUI fields" "status=$status"
fi

status="$(curl -sS -o "$WORK/proxy.initial.out" -w "%{http_code}" \
  --proxy "http://127.0.0.1:$MIXED_PORT_1" \
  --proxy-user "gui:pa:ss" \
  --max-time 8 \
  "http://127.0.0.1:$ORIGIN_PORT/" 2>>"$WORK/curl.err" || true)"
if [ "$status" = "200" ]; then
  ok "mixed HTTP proxy reaches local origin" "status=200 via port $MIXED_PORT_1"
else
  no "mixed HTTP proxy reaches local origin" "status=$status"
fi

status="$(http_status "$WORK/dns_api.json" -H "Authorization: Bearer $SECRET" "http://127.0.0.1:$CLASH_PORT/dns/query?name=localhost&type=A")"
if [ "$status" = "200" ]; then
  json_expect "Clash DNS query endpoint" "$WORK/dns_api.json" "data.get('name') == 'localhost' and isinstance(data.get('addresses'), list)" "GET /dns/query localhost"
else
  no "Clash DNS query endpoint" "status=$status"
fi

status="$(http_status "$WORK/proxies.initial.json" -H "Authorization: Bearer $SECRET" "http://127.0.0.1:$CLASH_PORT/proxies")"
if [ "$status" = "200" ]; then
  json_expect "Clash /proxies exposes GUI groups" "$WORK/proxies.initial.json" "all(k in data.get('proxies', {}) for k in ['GLOBAL', 'Select', 'Direct'])" "GLOBAL/Select/Direct groups"
else
  no "Clash /proxies exposes GUI groups" "status=$status"
fi

status="$(http_status "$WORK/select.block.out" -X PUT -H "Authorization: Bearer $SECRET" -H "Content-Type: application/json" --data '{"name":"block"}' "http://127.0.0.1:$CLASH_PORT/proxies/Direct")"
if [ "$status" = "204" ]; then
  ok "selector Direct can select block" "PUT /proxies/Direct"
else
  no "selector Direct can select block" "status=$status"
fi

status="$(http_status "$WORK/proxies.block.json" -H "Authorization: Bearer $SECRET" "http://127.0.0.1:$CLASH_PORT/proxies")"
if [ "$status" = "200" ]; then
  json_expect "selector now reflects block" "$WORK/proxies.block.json" "data.get('proxies', {}).get('Direct', {}).get('now') == 'block'" "Direct.now=block"
else
  no "selector now reflects block" "status=$status"
fi

status="$(http_status "$WORK/configs.set_direct.out" -X PATCH -H "Authorization: Bearer $SECRET" -H "Content-Type: application/json" --data '{"mode":"direct"}' "http://127.0.0.1:$CLASH_PORT/configs")"
if [ "$status" = "204" ]; then
  ok "Clash mode direct persisted request" "PATCH /configs mode=direct"
else
  no "Clash mode direct persisted request" "status=$status"
fi

stop_core "initial stop"

echo "== Restart with same CacheFile =="
start_core "restart" "$INITIAL_CONFIG" "$WORK/core.restart.log"

status="$(http_status "$WORK/configs.restart.json" -H "Authorization: Bearer $SECRET" "http://127.0.0.1:$CLASH_PORT/configs")"
if [ "$status" = "200" ]; then
  json_expect "Clash mode restored from CacheFile" "$WORK/configs.restart.json" "data.get('mode') == 'direct'" "mode=direct after restart"
else
  no "Clash mode restored from CacheFile" "status=$status"
fi

status="$(http_status "$WORK/proxies.restart.json" -H "Authorization: Bearer $SECRET" "http://127.0.0.1:$CLASH_PORT/proxies")"
if [ "$status" = "200" ]; then
  json_expect "selector choice restored from CacheFile" "$WORK/proxies.restart.json" "data.get('proxies', {}).get('Direct', {}).get('now') == 'block'" "Direct.now=block after restart"
else
  no "selector choice restored from CacheFile" "status=$status"
fi

status="$(http_status "$WORK/select.direct.out" -X PUT -H "Authorization: Bearer $SECRET" -H "Content-Type: application/json" --data '{"name":"direct"}' "http://127.0.0.1:$CLASH_PORT/proxies/Direct")"
if [ "$status" = "204" ]; then
  ok "selector Direct restored to direct" "PUT /proxies/Direct"
else
  no "selector Direct restored to direct" "status=$status"
fi

echo "== Reload rehearsal =="
status="$(http_status "$WORK/reload.json" -X POST -H "X-Admin-Token: $ADMIN_TOKEN" -H "Content-Type: application/json" --data-binary "{\"path\":\"$RELOAD_CONFIG\"}" "http://127.0.0.1:$ADMIN_PORT/reload")"
if [ "$status" = "200" ]; then
  json_expect "core admin reload accepted" "$WORK/reload.json" "data.get('ok') is True and data.get('event') == 'reload'" "POST /reload ok=true"
else
  no "core admin reload accepted" "status=$status"
fi

if wait_port_closed "$MIXED_PORT_1"; then
  ok "old mixed port closed after reload" "127.0.0.1:$MIXED_PORT_1"
else
  no "old mixed port closed after reload" "port remained open"
fi
if wait_port_open "$MIXED_PORT_2"; then
  ok "new mixed port open after reload" "127.0.0.1:$MIXED_PORT_2"
else
  no "new mixed port open after reload" "port did not open"
fi

status="$(curl -sS -o "$WORK/proxy.reload.out" -w "%{http_code}" \
  --proxy "http://127.0.0.1:$MIXED_PORT_2" \
  --proxy-user "gui:pa:ss" \
  --max-time 8 \
  "http://127.0.0.1:$ORIGIN_PORT/" 2>>"$WORK/curl.err" || true)"
if [ "$status" = "200" ]; then
  ok "reloaded mixed HTTP proxy reaches local origin" "status=200 via port $MIXED_PORT_2"
else
  no "reloaded mixed HTTP proxy reaches local origin" "status=$status"
fi

status="$(http_status "$WORK/configs.reload.json" -H "Authorization: Bearer $SECRET" "http://127.0.0.1:$CLASH_PORT/configs")"
if [ "$status" = "200" ]; then
  json_expect "Clash /configs reflects reloaded mixed port" "$WORK/configs.reload.json" "data.get('mixed-port') == $MIXED_PORT_2" "mixed-port=$MIXED_PORT_2"
else
  no "Clash /configs reflects reloaded mixed port" "status=$status"
fi

status="$(http_status "$WORK/explain.reload.json" -X POST -H "X-Admin-Token: $ADMIN_TOKEN" -H "Content-Type: application/json" --data '{"dest":"rehearsal-block.test:80","network":"tcp","protocol":"http"}' "http://127.0.0.1:$ADMIN_PORT/explain")"
if [ "$status" = "200" ]; then
  json_expect "core admin /explain uses reloaded route" "$WORK/explain.reload.json" "data.get('outbound') == 'Block'" "outbound=Block"
else
  no "core admin /explain uses reloaded route" "status=$status"
fi

curl -sS -o "$WORK/proxy.slow.out" \
  --proxy "http://127.0.0.1:$MIXED_PORT_2" \
  --proxy-user "gui:pa:ss" \
  --max-time 10 \
  "http://127.0.0.1:$ORIGIN_PORT/slow" \
  2>>"$WORK/curl.err" &
SLOW_CURL_PID=$!
sleep 0.5

status="$(http_status "$WORK/connections.active.json" -H "Authorization: Bearer $SECRET" "http://127.0.0.1:$CLASH_PORT/connections")"
if [ "$status" = "200" ]; then
  json_expect "Clash /connections snapshot shape" "$WORK/connections.active.json" "isinstance(data.get('connections'), list)" "connections array present"
  if python3 - "$WORK/connections.active.json" <<'PY'
import json
import sys
data = json.load(open(sys.argv[1]))
raise SystemExit(0 if len(data.get("connections", [])) > 0 else 1)
PY
  then
    ok "Clash /connections observed active request" "slow local origin request visible"
  else
    warn "Clash /connections active observation" "snapshot shape valid but active request was not observed"
  fi
else
  no "Clash /connections snapshot shape" "status=$status"
fi

if [ -n "${SLOW_CURL_PID:-}" ]; then
  wait "$SLOW_CURL_PID" 2>/dev/null || true
  SLOW_CURL_PID=""
fi

stop_core "final stop"
finish
