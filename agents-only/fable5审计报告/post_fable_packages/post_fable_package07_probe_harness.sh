#!/usr/bin/env bash
# post_fable_package07 — GUI.for.SingBox process-contract equivalence probe
#
# Reproduces EXACTLY what GUI.for SingBox 1.19.0 does to the kernel at the
# process level, minus the desktop window (an agent cannot click a Wails GUI):
#   - lays out  <work>/data/sing-box/sing-box  + config.json  (GUI's path contract)
#   - launches with GUI's exact arg vector: run --disable-color -c <abs>/config.json -D <abs>
#   - asserts the GUI start keyword `sing-box started` appears (kernelApi.ts resolves on it)
#   - asserts the inbound + Clash API bind
#   - drives traffic through SOCKS5 and HTTP CONNECT (the methods GUI/system-proxy use)
#   - exercises the Clash API telemetry path GUI reads (/configs, /proxies, Bearer auth)
#   - stops via SIGINT (GUI KillProcess Unix path) and confirms clean exit + port release
#   - restart cycle: stop -> immediate restart, confirms same-port rebind (no EADDRINUSE)
#
# NOT a fix; product code is untouched. See the companion note for findings.
#
# Requirements: a kernel built with the GUI runtime profile, e.g.
#   cargo build -p app --bin app --features gui_runtime
# (the default `cargo build -p app` binary remains router-only and is NOT a
#  GUI drop-in proxy runtime — see note finding F-2.)
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
KERNEL="${KERNEL:-$REPO/target/debug/app}"
WORK="${WORK:-/tmp/pf07}"
MIXED_PORT=20122
CLASH_PORT=20123
ORIGIN_PORT=18080
SECRET=pf07probe
PASS=0; FAIL=0
ok(){ echo "  [PASS] $*"; PASS=$((PASS+1)); }
no(){ echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }

[ -x "$KERNEL" ] || {
  echo "kernel not found/executable: $KERNEL"
  echo "build GUI runtime with: cargo build -p app --bin app --features gui_runtime"
  exit 2
}

# --- GUI working-config (passes Rust strict validator; mirrors GUI default shape
#     minus the DNS `domain_resolver` gap recorded as finding F-1) ---
mkdir -p "$WORK/data/sing-box"
cat > "$WORK/data/sing-box/config.json" <<EOF
{
  "log": { "level": "info", "timestamp": false },
  "experimental": {
    "clash_api": { "external_controller": "127.0.0.1:$CLASH_PORT", "secret": "$SECRET", "default_mode": "rule" }
  },
  "inbounds": [
    { "type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": $MIXED_PORT }
  ],
  "outbounds": [
    { "type": "selector", "tag": "select", "outbounds": ["direct"], "default": "direct" },
    { "type": "direct", "tag": "direct" },
    { "type": "block", "tag": "block" }
  ],
  "route": { "rules": [ { "clash_mode": "direct", "action": "route", "outbound": "direct" } ], "final": "select" }
}
EOF

# GUI places the kernel as <BasePath>/data/sing-box/sing-box (constant/kernel.ts).
ln -sf "$KERNEL" "$WORK/data/sing-box/sing-box"
ABS="$WORK/data/sing-box"

# local origin server (used because the sandbox may block external network;
# a local target still exercises inbound -> route -> direct outbound -> origin)
python3 -m http.server "$ORIGIN_PORT" --bind 127.0.0.1 >"$WORK/origin.log" 2>&1 &
ORIGIN=$!
trap 'kill $ORIGIN 2>/dev/null' EXIT
sleep 1

launch(){ # $1 = logfile -> echoes pid
  "$ABS/sing-box" run --disable-color -c "$ABS/config.json" -D "$ABS" >"$1" 2>&1 &
  echo $!
}
wait_started(){ # $1 = logfile
  for _ in $(seq 1 40); do grep -q "sing-box started" "$1" && return 0; sleep 0.3; done; return 1
}
stop_sigint(){ # $1 = pid ; echoes exit seconds
  local t0 t1; t0=$(date +%s.%N); kill -INT "$1" 2>/dev/null
  for _ in $(seq 1 40); do kill -0 "$1" 2>/dev/null || break; sleep 0.25; done
  t1=$(date +%s.%N)
  if kill -0 "$1" 2>/dev/null; then kill -9 "$1" 2>/dev/null; echo "TIMEOUT"; else echo "$(echo "$t1-$t0"|bc)"; fi
}

echo "== run1: GUI-exact launch =="
P1=$(launch "$WORK/probe.log")
if wait_started "$WORK/probe.log"; then ok "startup keyword 'sing-box started' observed (GUI resolves start promise)"; else no "no 'sing-box started'"; fi
nc -z 127.0.0.1 $MIXED_PORT 2>/dev/null && ok "mixed inbound bound :$MIXED_PORT" || no "mixed not bound"
nc -z 127.0.0.1 $CLASH_PORT 2>/dev/null && ok "clash api bound :$CLASH_PORT" || no "clash not bound"

echo "== traffic (non-TUN) =="
base=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:$ORIGIN_PORT/ --max-time 4)
[ "$base" = 200 ] && ok "origin baseline 200" || no "origin baseline $base"
s5=$(curl -s -o /dev/null -w "%{http_code}" --socks5 127.0.0.1:$MIXED_PORT http://127.0.0.1:$ORIGIN_PORT/ --max-time 5)
[ "$s5" = 200 ] && ok "SOCKS5 proxy path 200" || no "SOCKS5 path $s5"
ct=$(curl -s -o /dev/null -w "%{http_code}" -p -x http://127.0.0.1:$MIXED_PORT http://127.0.0.1:$ORIGIN_PORT/ --max-time 5)
[ "$ct" = 200 ] && ok "HTTP CONNECT tunnel 200" || no "CONNECT tunnel $ct"
fwd=$(curl -s -o /dev/null -w "%{http_code}" -x http://127.0.0.1:$MIXED_PORT http://127.0.0.1:$ORIGIN_PORT/ --max-time 5)
[ "$fwd" = 200 ] && ok "plain-HTTP forward GET 200 (F-3 closed by package13)" || no "plain-HTTP forward GET -> $fwd (expected 200)"

echo "== clash api telemetry (GUI reads these) =="
cfg=$(curl -s -H "Authorization: Bearer $SECRET" http://127.0.0.1:$CLASH_PORT/configs --max-time 5)
echo "$cfg" | grep -q "mixed-port" && ok "/configs returns clash config json" || no "/configs unexpected: $(echo "$cfg"|head -c 80)"
pr=$(curl -s -H "Authorization: Bearer $SECRET" http://127.0.0.1:$CLASH_PORT/proxies --max-time 5)
echo "$pr" | grep -q '"proxies"' && ok "/proxies returns proxy set (node selection)" || no "/proxies unexpected"
na=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:$CLASH_PORT/configs --max-time 5)
[ "$na" = 401 ] && ok "clash api rejects missing Bearer token (401)" || no "clash api no-token -> $na (expected 401)"

echo "== stop (SIGINT = GUI KillProcess Unix) =="
secs=$(stop_sigint "$P1")
[ "$secs" != TIMEOUT ] && ok "exited on SIGINT in ${secs}s (< Go FatalStopTimeout 10s)" || no "did not exit in 10s (SIGKILLed)"
sleep 0.5
nc -z 127.0.0.1 $MIXED_PORT 2>/dev/null && no "port still bound after stop" || ok "port :$MIXED_PORT released after stop"

echo "== restart cycle (GUI restartCore = stop -> start new process) =="
P2=$(launch "$WORK/probe2.log")
if wait_started "$WORK/probe2.log"; then ok "rebind/restart started (pid $P1 -> $P2)"; else no "restart failed to start"; fi
grep -iqE "address already in use|EADDRINUSE" "$WORK/probe2.log" && no "EADDRINUSE on immediate rebind" || ok "same-port rebind clean (no EADDRINUSE)"
stop_sigint "$P2" >/dev/null

echo
echo "== summary: PASS=$PASS FAIL=$FAIL =="
[ "$FAIL" -eq 0 ] && echo "CONTRACT-EQUIVALENCE PROBE: PASS" || echo "CONTRACT-EQUIVALENCE PROBE: FAIL"
exit "$FAIL"
