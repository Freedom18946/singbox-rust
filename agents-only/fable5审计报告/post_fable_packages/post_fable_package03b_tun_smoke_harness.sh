#!/usr/bin/env bash
# post_fable_package03b — TUN privileged dataplane smoke harness.
#
# Modes:
#   PF03B_MODE=auto       normal when non-root, privileged when root
#   PF03B_MODE=normal     expect permission/backend failure before "sing-box started"
#   PF03B_MODE=privileged require root and prove OS route -> Rust TUN -> configured HTTP outbound
#
# Dataplane coverage (post003 UDP/IPv6 extension):
#   * TCP/IPv4 : live, gating. curl http://198.18.0.2:18080 routed into utun -> HTTP CONNECT outbound.
#   * TCP/IPv6 : live, gating when PF03B_PROBE_IPV6=1 (default). curl http://[fd00:db8::2]:18080
#                routed into utun -> exercises the new IPv6 reply-packet path; the outbound dial is
#                IPv4 loopback to the same stub, so there is no routing loop.
#   * UDP      : the Enhanced UDP NAT (parse -> route -> outbound send -> reverse relay -> write back)
#                is verified by the deterministic unit test
#                `sb-adapters inbound::tun_enhanced::tests::udp_forward_direct_echo_relays_back`
#                (real DirectConnector UDP socket + reverse relay, no root). A single-host *live*
#                UDP-through-utun proof with a `direct` outbound is not feasible: `direct` dials the
#                literal destination, which `auto_route` sends back into utun (routing loop). The
#                shared utun device read path is proven live by the TCP probes; `parse_raw_udp` is
#                unit-tested. So UDP is proven by composition, not by a live curl here.
#
# Artifacts are written under WORK only; no repo-root scratch files.
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
MODE="${PF03B_MODE:-auto}"
KERNEL="${KERNEL:-$REPO/target/debug/app}"
WORK="${WORK:-/tmp/pf03b-tun-smoke}"
TARGET_IP="${PF03B_TARGET_IP:-198.18.0.2}"
TARGET_PORT="${PF03B_TARGET_PORT:-18080}"
TARGET_CIDR="${PF03B_TARGET_CIDR:-198.18.0.0/16}"
PROBE_IPV6="${PF03B_PROBE_IPV6:-1}"
TARGET_IP6="${PF03B_TARGET_IP6:-fd00:db8::2}"
TARGET_CIDR6="${PF03B_TARGET_CIDR6:-fd00:db8::/32}"
TUN_ADDR6="${PF03B_TUN_ADDR6:-fd00:19::1/64}"
SKIP_BUILD="${PF03B_SKIP_BUILD:-0}"
UID_NOW="$(id -u)"
PLATFORM="$(uname -s | tr '[:upper:]' '[:lower:]')"

case "$PLATFORM" in
  darwin) DEFAULT_TUN_NAME="utun9" ;;
  linux) DEFAULT_TUN_NAME="tun0" ;;
  *) DEFAULT_TUN_NAME="tun0" ;;
esac
TUN_NAME="${PF03B_TUN_NAME:-$DEFAULT_TUN_NAME}"

case "$MODE" in
  auto)
    if [ "$UID_NOW" = "0" ]; then EFFECTIVE_MODE="privileged"; else EFFECTIVE_MODE="normal"; fi
    ;;
  normal|privileged)
    EFFECTIVE_MODE="$MODE"
    ;;
  *)
    echo "invalid PF03B_MODE=$MODE (expected auto|normal|privileged)" >&2
    exit 2
    ;;
esac

mkdir -p "$WORK"
RESULT="$WORK/result.json"
CONFIG="$WORK/config.json"
APP_LOG="$WORK/app.log"
BUILD_LOG="$WORK/build.log"
CHECK_LOG="$WORK/check.log"
PROXY_LOG="$WORK/connect_proxy.log"
PROXY_PORT_FILE="$WORK/connect_proxy.port"
CURL_BODY="$WORK/curl.body"
CURL_ERR="$WORK/curl.err"
CURL_STATUS="$WORK/curl.status"

BUILD_STATUS="not_run"
CONFIG_STATUS="not_run"
STARTUP_STATUS="not_run"
STARTED_SEEN="false"
CURL_STATUS_VALUE=""
CURL_SUCCESS="false"
OUTBOUND_HIT="false"
CURL6_STATUS_VALUE=""
CURL6_SUCCESS="false"
OUTBOUND6_HIT="false"
CLEANUP_STATUS="not_run"
MESSAGE=""
APP_PID=""
PROXY_PID=""

log() {
  printf '[pf03b][%s] %s\n' "$EFFECTIVE_MODE" "$*"
}

json_result() {
  local status="$1"
  local exit_code="$2"
  local message="$3"
  RESULT_STATUS="$status" \
  RESULT_EXIT="$exit_code" \
  RESULT_MESSAGE="$message" \
  PF03B_MODE_REQUESTED="$MODE" \
  PF03B_MODE_EFFECTIVE="$EFFECTIVE_MODE" \
  PF03B_PLATFORM="$PLATFORM" \
  PF03B_UID="$UID_NOW" \
  PF03B_KERNEL="$KERNEL" \
  PF03B_WORK="$WORK" \
  PF03B_TUN_NAME="$TUN_NAME" \
  PF03B_TARGET_IP="$TARGET_IP" \
  PF03B_TARGET_PORT="$TARGET_PORT" \
  PF03B_TARGET_CIDR="$TARGET_CIDR" \
  PF03B_BUILD_STATUS="$BUILD_STATUS" \
  PF03B_CONFIG_STATUS="$CONFIG_STATUS" \
  PF03B_STARTUP_STATUS="$STARTUP_STATUS" \
  PF03B_STARTED_SEEN="$STARTED_SEEN" \
  PF03B_CURL_STATUS="$CURL_STATUS_VALUE" \
  PF03B_CURL_SUCCESS="$CURL_SUCCESS" \
  PF03B_OUTBOUND_HIT="$OUTBOUND_HIT" \
  PF03B_PROBE_IPV6="$PROBE_IPV6" \
  PF03B_TARGET_IP6="$TARGET_IP6" \
  PF03B_TARGET_CIDR6="$TARGET_CIDR6" \
  PF03B_CURL6_STATUS="$CURL6_STATUS_VALUE" \
  PF03B_CURL6_SUCCESS="$CURL6_SUCCESS" \
  PF03B_OUTBOUND6_HIT="$OUTBOUND6_HIT" \
  PF03B_CLEANUP_STATUS="$CLEANUP_STATUS" \
  python3 - <<'PY' > "$RESULT"
import json
import os

def bool_env(name):
    return os.environ.get(name, "").lower() == "true"

def bool_env_int(name):
    return os.environ.get(name, "0") == "1"

data = {
    "status": os.environ["RESULT_STATUS"],
    "exit_code": int(os.environ["RESULT_EXIT"]),
    "message": os.environ["RESULT_MESSAGE"],
    "mode_requested": os.environ["PF03B_MODE_REQUESTED"],
    "mode_effective": os.environ["PF03B_MODE_EFFECTIVE"],
    "platform": os.environ["PF03B_PLATFORM"],
    "uid": int(os.environ["PF03B_UID"]),
    "kernel": os.environ["PF03B_KERNEL"],
    "work": os.environ["PF03B_WORK"],
    "tun_name": os.environ["PF03B_TUN_NAME"],
    "target_ip": os.environ["PF03B_TARGET_IP"],
    "target_port": int(os.environ["PF03B_TARGET_PORT"]),
    "target_cidr": os.environ["PF03B_TARGET_CIDR"],
    "probe_ipv6": bool_env_int("PF03B_PROBE_IPV6"),
    "target_ip6": os.environ["PF03B_TARGET_IP6"],
    "target_cidr6": os.environ["PF03B_TARGET_CIDR6"],
    "stages": {
        "binary": os.environ["PF03B_BUILD_STATUS"],
        "config_validation": os.environ["PF03B_CONFIG_STATUS"],
        "tun_startup": os.environ["PF03B_STARTUP_STATUS"],
        "sing_box_started_seen": bool_env("PF03B_STARTED_SEEN"),
        "curl_http_status": os.environ["PF03B_CURL_STATUS"],
        "curl_success": bool_env("PF03B_CURL_SUCCESS"),
        "configured_outbound_hit": bool_env("PF03B_OUTBOUND_HIT"),
        "curl6_http_status": os.environ["PF03B_CURL6_STATUS"],
        "curl6_success": bool_env("PF03B_CURL6_SUCCESS"),
        "configured_outbound6_hit": bool_env("PF03B_OUTBOUND6_HIT"),
        "cleanup": os.environ["PF03B_CLEANUP_STATUS"],
    },
    "artifacts": {
        "config": "config.json",
        "app_log": "app.log",
        "build_log": "build.log",
        "check_log": "check.log",
        "connect_proxy_log": "connect_proxy.log",
        "curl_body": "curl.body",
        "curl_err": "curl.err",
        "before_interfaces": "before_interfaces.txt",
        "before_routes": "before_routes.txt",
        "before_route_get": "before_route_get.txt",
        "after_interfaces": "after_interfaces.txt",
        "after_routes": "after_routes.txt",
        "after_route_get": "after_route_get.txt",
        "final_interfaces": "final_interfaces.txt",
        "final_routes": "final_routes.txt",
        "final_route_get": "final_route_get.txt",
    },
}
print(json.dumps(data, indent=2, sort_keys=True))
PY
}

capture_state() {
  local prefix="$1"
  case "$PLATFORM" in
    darwin)
      ifconfig > "$WORK/${prefix}_interfaces.txt" 2>&1 || true
      netstat -rn > "$WORK/${prefix}_routes.txt" 2>&1 || true
      route -n get "$TARGET_IP" > "$WORK/${prefix}_route_get.txt" 2>&1 || true
      ;;
    linux)
      ip addr > "$WORK/${prefix}_interfaces.txt" 2>&1 || true
      ip route show table all > "$WORK/${prefix}_routes.txt" 2>&1 || true
      ip route get "$TARGET_IP" > "$WORK/${prefix}_route_get.txt" 2>&1 || true
      ;;
    *)
      uname -a > "$WORK/${prefix}_interfaces.txt" 2>&1 || true
      netstat -rn > "$WORK/${prefix}_routes.txt" 2>&1 || true
      : > "$WORK/${prefix}_route_get.txt"
      ;;
  esac
}

stop_processes() {
  if [ -n "${APP_PID:-}" ] && kill -0 "$APP_PID" 2>/dev/null; then
    kill -INT "$APP_PID" 2>/dev/null || true
    for _ in $(seq 1 40); do
      kill -0 "$APP_PID" 2>/dev/null || break
      sleep 0.25
    done
    if kill -0 "$APP_PID" 2>/dev/null; then
      kill -TERM "$APP_PID" 2>/dev/null || true
      sleep 0.5
    fi
    if kill -0 "$APP_PID" 2>/dev/null; then
      kill -KILL "$APP_PID" 2>/dev/null || true
    fi
  fi
  if [ -n "${PROXY_PID:-}" ] && kill -0 "$PROXY_PID" 2>/dev/null; then
    kill "$PROXY_PID" 2>/dev/null || true
  fi
}

manual_route_cleanup_if_needed() {
  if [ "$UID_NOW" != "0" ]; then
    return 0
  fi
  case "$PLATFORM" in
    darwin)
      if ! grep -q "$TARGET_CIDR" "$WORK/before_routes.txt" 2>/dev/null && \
         grep -q "$TARGET_CIDR" "$WORK/after_routes.txt" 2>/dev/null; then
        route delete "$TARGET_CIDR" > "$WORK/manual_route_cleanup.log" 2>&1 || true
      fi
      if [ "$PROBE_IPV6" = "1" ] && \
         ! grep -q "$TARGET_CIDR6" "$WORK/before_routes.txt" 2>/dev/null && \
         grep -q "$TARGET_CIDR6" "$WORK/after_routes.txt" 2>/dev/null; then
        route -inet6 delete "$TARGET_CIDR6" >> "$WORK/manual_route_cleanup.log" 2>&1 || true
      fi
      ;;
    linux)
      if ! grep -q "$TARGET_CIDR" "$WORK/before_routes.txt" 2>/dev/null && \
         grep -q "$TARGET_CIDR" "$WORK/after_routes.txt" 2>/dev/null; then
        ip route delete "$TARGET_CIDR" > "$WORK/manual_route_cleanup.log" 2>&1 || true
      fi
      if [ "$PROBE_IPV6" = "1" ] && \
         ! grep -q "$TARGET_CIDR6" "$WORK/before_routes.txt" 2>/dev/null && \
         grep -q "$TARGET_CIDR6" "$WORK/after_routes.txt" 2>/dev/null; then
        ip -6 route delete "$TARGET_CIDR6" >> "$WORK/manual_route_cleanup.log" 2>&1 || true
      fi
      ;;
  esac
}

evaluate_cleanup() {
  if [ -n "${APP_PID:-}" ] && kill -0 "$APP_PID" 2>/dev/null; then
    echo "failed_app_process_still_running"
    return
  fi
  if [ -n "${PROXY_PID:-}" ] && kill -0 "$PROXY_PID" 2>/dev/null; then
    echo "failed_proxy_process_still_running"
    return
  fi
  if [ "$EFFECTIVE_MODE" = "privileged" ] && \
     grep -q "$TUN_NAME" "$WORK/final_route_get.txt" 2>/dev/null && \
     ! grep -q "$TUN_NAME" "$WORK/before_route_get.txt" 2>/dev/null; then
    echo "failed_target_route_still_points_to_${TUN_NAME}"
    return
  fi
  echo "complete"
}

finish() {
  local status="$1"
  local code="$2"
  local message="$3"
  MESSAGE="$message"
  stop_processes
  capture_state "after"
  manual_route_cleanup_if_needed
  capture_state "final"
  CLEANUP_STATUS="$(evaluate_cleanup)"
  if [ "$status" = "PASS" ] && [ "$CLEANUP_STATUS" != "complete" ]; then
    status="FAIL"
    code="1"
    message="$message; cleanup verification failed: $CLEANUP_STATUS"
  fi
  json_result "$status" "$code" "$message"
  log "$message"
  log "result: $RESULT"
  exit "$code"
}

write_proxy_stub() {
  cat > "$WORK/connect_proxy.py" <<'PY'
import os
import socketserver
import sys
import time

log_path = os.environ["PF03B_PROXY_LOG"]
port_path = os.environ["PF03B_PROXY_PORT_FILE"]
target = f"{os.environ['PF03B_TARGET_IP']}:{os.environ['PF03B_TARGET_PORT']}"

def log(line):
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(line.rstrip() + "\n")
        fh.flush()

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(8)
        data = b""
        while b"\r\n\r\n" not in data and len(data) < 8192:
            chunk = self.request.recv(1024)
            if not chunk:
                break
            data += chunk
        text = data.decode("iso-8859-1", errors="replace")
        first = text.splitlines()[0] if text.splitlines() else ""
        log(f"CONNECT_LINE {first}")
        if not first.startswith("CONNECT "):
            self.request.sendall(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")
            return
        self.request.sendall(b"HTTP/1.1 200 Connection Established\r\nConnection: keep-alive\r\n\r\n")
        tunneled = b""
        try:
            while b"\r\n\r\n" not in tunneled and len(tunneled) < 8192:
                chunk = self.request.recv(1024)
                if not chunk:
                    break
                tunneled += chunk
        except TimeoutError:
            pass
        tunneled_text = tunneled.decode("iso-8859-1", errors="replace")
        tunneled_first = tunneled_text.splitlines()[0] if tunneled_text.splitlines() else ""
        log(f"TUNNELED_LINE {tunneled_first}")
        body = f"PF03B-TUN-OK {target}\n".encode("ascii")
        response = (
            b"HTTP/1.1 200 OK\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"Content-Type: text/plain\r\nConnection: close\r\n\r\n"
            + body
        )
        self.request.sendall(response)

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

with Server(("127.0.0.1", 0), Handler) as server:
    port = server.server_address[1]
    with open(port_path, "w", encoding="utf-8") as fh:
        fh.write(str(port))
    log(f"LISTEN 127.0.0.1:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
PY
}

start_proxy() {
  : > "$PROXY_LOG"
  rm -f "$PROXY_PORT_FILE"
  write_proxy_stub
  PF03B_PROXY_LOG="$PROXY_LOG" \
  PF03B_PROXY_PORT_FILE="$PROXY_PORT_FILE" \
  PF03B_TARGET_IP="$TARGET_IP" \
  PF03B_TARGET_PORT="$TARGET_PORT" \
  python3 "$WORK/connect_proxy.py" &
  PROXY_PID=$!
  for _ in $(seq 1 50); do
    [ -s "$PROXY_PORT_FILE" ] && return 0
    sleep 0.1
  done
  return 1
}

generate_config() {
  local proxy_port="$1"
  local address_json="\"172.19.0.1/30\""
  local route_address_json="\"$TARGET_CIDR\""
  local rules_json="      { \"ip_cidr\": \"$TARGET_CIDR\", \"outbound\": \"pf03b-http-out\" }"
  if [ "$PROBE_IPV6" = "1" ]; then
    address_json="$address_json, \"$TUN_ADDR6\""
    route_address_json="$route_address_json, \"$TARGET_CIDR6\""
    rules_json="$rules_json,
      { \"ip_cidr\": \"$TARGET_CIDR6\", \"outbound\": \"pf03b-http-out\" }"
  fi
  cat > "$CONFIG" <<EOF
{
  "log": { "level": "debug", "timestamp": false },
  "inbounds": [
    {
      "type": "tun",
      "tag": "pf03b-tun-in",
      "stack": "mixed",
      "interface_name": "$TUN_NAME",
      "address": [$address_json],
      "route_address": [$route_address_json],
      "route_exclude_address": ["127.0.0.0/8", "::1/128"],
      "auto_route": true,
      "strict_route": true
    }
  ],
  "outbounds": [
    { "type": "http", "tag": "pf03b-http-out", "server": "127.0.0.1", "port": $proxy_port },
    { "type": "block", "tag": "block" }
  ],
  "route": {
    "rules": [
$rules_json
    ],
    "final": "block"
  }
}
EOF
}

wait_for_started_or_exit() {
  local timeout_steps="$1"
  for _ in $(seq 1 "$timeout_steps"); do
    if grep -q "sing-box started" "$APP_LOG" 2>/dev/null; then
      STARTED_SEEN="true"
      return 0
    fi
    if [ -n "${APP_PID:-}" ] && ! kill -0 "$APP_PID" 2>/dev/null; then
      return 1
    fi
    sleep 0.25
  done
  return 2
}

run_build_if_needed() {
  if [ "$SKIP_BUILD" = "1" ]; then
    if [ -x "$KERNEL" ]; then
      BUILD_STATUS="skipped_existing"
      return 0
    fi
    BUILD_STATUS="skipped_missing_kernel"
    return 1
  fi

  if [ "$UID_NOW" = "0" ]; then
    if [ -x "$KERNEL" ]; then
      BUILD_STATUS="skipped_root_existing"
      return 0
    fi
    BUILD_STATUS="root_build_refused_missing_kernel"
    return 1
  fi

  log "building app binary"
  (cd "$REPO" && cargo build -p app --bin app --features adapters,clash_api) > "$BUILD_LOG" 2>&1
  local rc=$?
  if [ "$rc" -eq 0 ] && [ -x "$KERNEL" ]; then
    BUILD_STATUS="pass"
    return 0
  fi
  BUILD_STATUS="fail"
  return "$rc"
}

run_config_check() {
  log "validating config"
  "$KERNEL" check --disable-color -c "$CONFIG" --schema-v2-validate > "$CHECK_LOG" 2>&1
  local rc=$?
  printf 'PF03B_CHECK_RC=%s\n' "$rc" >> "$CHECK_LOG"
  if [ "$rc" -eq 0 ] || grep -q "Config validation passed" "$CHECK_LOG"; then
    CONFIG_STATUS="pass"
    return 0
  fi
  CONFIG_STATUS="fail"
  return "$rc"
}

run_normal() {
  if [ "$UID_NOW" = "0" ]; then
    STARTUP_STATUS="not_run_root_user"
    finish "BLOCKED" 3 "normal mode requires a non-root user to prove permission failure"
  fi

  log "launching normal-user TUN startup probe"
  "$KERNEL" run --disable-color -c "$CONFIG" -D "$WORK" > "$APP_LOG" 2>&1 &
  APP_PID=$!
  wait_for_started_or_exit 80 || true

  local app_rc=0
  if kill -0 "$APP_PID" 2>/dev/null; then
    STARTUP_STATUS="unexpected_still_running"
    finish "FAIL" 1 "normal mode did not fail quickly; app still running"
  else
    wait "$APP_PID"
    app_rc=$?
  fi

  if [ "$app_rc" -ne 0 ] && [ "$STARTED_SEEN" = "false" ] && \
     grep -Eiq "Operation not permitted|Permission denied|failed to prepare TUN runtime backend|runtime startup blocked by adapter errors" "$APP_LOG"; then
    STARTUP_STATUS="permission_failed_before_started"
    finish "PASS" 0 "normal-user TUN startup failed before 'sing-box started' with a loud permission/backend error"
  fi

  STARTUP_STATUS="unexpected_result_rc_${app_rc}_started_${STARTED_SEEN}"
  finish "FAIL" 1 "normal-user probe did not match expected pre-start permission failure"
}

run_privileged() {
  if [ "$UID_NOW" != "0" ]; then
    STARTUP_STATUS="not_run_missing_privilege"
    finish "BLOCKED" 3 "privileged mode requires root/admin privileges; rerun with sudo -E after building the kernel"
  fi

  log "launching privileged TUN dataplane probe"
  "$KERNEL" run --disable-color -c "$CONFIG" -D "$WORK" > "$APP_LOG" 2>&1 &
  APP_PID=$!
  if ! wait_for_started_or_exit 120; then
    STARTUP_STATUS="failed_before_started"
    finish "FAIL" 1 "privileged TUN probe failed before 'sing-box started'"
  fi
  STARTUP_STATUS="started"

  capture_state "started"
  log "curling ${TARGET_IP}:${TARGET_PORT} without proxy flags"
  CURL_STATUS_VALUE="$(curl --noproxy '*' -sS -o "$CURL_BODY" -w "%{http_code}" --max-time 10 "http://${TARGET_IP}:${TARGET_PORT}/pf03b" 2> "$CURL_ERR" || true)"
  printf '%s\n' "$CURL_STATUS_VALUE" > "$CURL_STATUS"
  if [ "$CURL_STATUS_VALUE" = "200" ] && grep -q "PF03B-TUN-OK ${TARGET_IP}:${TARGET_PORT}" "$CURL_BODY" 2>/dev/null; then
    CURL_SUCCESS="true"
  fi
  if grep -q "CONNECT_LINE CONNECT ${TARGET_IP}:${TARGET_PORT} " "$PROXY_LOG" 2>/dev/null; then
    OUTBOUND_HIT="true"
  fi

  if [ "$PROBE_IPV6" = "1" ]; then
    log "curling [${TARGET_IP6}]:${TARGET_PORT} without proxy flags (IPv6 TCP)"
    CURL6_STATUS_VALUE="$(curl -g --noproxy '*' -sS -o "$WORK/curl6.body" -w "%{http_code}" --max-time 10 "http://[${TARGET_IP6}]:${TARGET_PORT}/pf03b" 2> "$WORK/curl6.err" || true)"
    printf '%s\n' "$CURL6_STATUS_VALUE" > "$WORK/curl6.status"
    if [ "$CURL6_STATUS_VALUE" = "200" ] && grep -q "PF03B-TUN-OK ${TARGET_IP}:${TARGET_PORT}" "$WORK/curl6.body" 2>/dev/null; then
      CURL6_SUCCESS="true"
    fi
    # The proxy stub logs the CONNECT target host; IPv6 hosts may appear bracketed or bare.
    if grep -Eq "CONNECT_LINE CONNECT (\[${TARGET_IP6}\]|${TARGET_IP6}):${TARGET_PORT} " "$PROXY_LOG" 2>/dev/null; then
      OUTBOUND6_HIT="true"
    fi
  fi

  local v4_ok="false"
  local v6_ok="true"
  if [ "$CURL_SUCCESS" = "true" ] && [ "$OUTBOUND_HIT" = "true" ]; then
    v4_ok="true"
  fi
  if [ "$PROBE_IPV6" = "1" ]; then
    if [ "$CURL6_SUCCESS" = "true" ] && [ "$OUTBOUND6_HIT" = "true" ]; then
      v6_ok="true"
    else
      v6_ok="false"
    fi
  fi

  if [ "$v4_ok" = "true" ] && [ "$v6_ok" = "true" ]; then
    if [ "$PROBE_IPV6" = "1" ]; then
      finish "PASS" 0 "privileged TUN traffic (TCP IPv4 + IPv6) reached the configured HTTP outbound and returned through the tunnel"
    else
      finish "PASS" 0 "privileged TUN traffic reached the configured HTTP outbound and returned through the tunnel"
    fi
  fi

  finish "FAIL" 1 "privileged TUN startup occurred but dataplane/outbound proof failed (v4_ok=$v4_ok v6_ok=$v6_ok)"
}

log "repo=$REPO"
log "work=$WORK"
log "mode requested=$MODE effective=$EFFECTIVE_MODE uid=$UID_NOW platform=$PLATFORM tun=$TUN_NAME"
rm -f "$APP_LOG" "$CHECK_LOG" "$PROXY_LOG" "$PROXY_PORT_FILE" "$CURL_BODY" "$CURL_ERR" "$CURL_STATUS" "$RESULT"
capture_state "before"

if ! run_build_if_needed; then
  finish "FAIL" 1 "binary build/existence check failed"
fi

if ! start_proxy; then
  finish "FAIL" 1 "failed to start local HTTP CONNECT proof stub"
fi
PROXY_PORT="$(cat "$PROXY_PORT_FILE")"
log "local CONNECT proof stub listening on 127.0.0.1:$PROXY_PORT"
generate_config "$PROXY_PORT"

if ! run_config_check; then
  finish "FAIL" 1 "config validation failed"
fi

case "$EFFECTIVE_MODE" in
  normal) run_normal ;;
  privileged) run_privileged ;;
esac
