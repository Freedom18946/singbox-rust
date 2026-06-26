#!/usr/bin/env bash
# post_fable_package04b — WireGuard live round-trip proof vs Go sing-box.
#
# Topology (single-host loopback, no root):
#   Rust app (WG client)        Go sing-box (WG server)       Python HTTP stub
#     endpoint: 10.0.0.2/32        endpoint: 10.0.0.1/32          127.0.0.1:STUB
#     listen: R                    listen: W                      (CONNECT proxy)
#     peer: Go pub, 127.0.0.1:W    peer: Rust pub, 127.0.0.1:R
#     mixed inbound: 127.0.0.1:RM  mixed inbound: 127.0.0.1:GM
#     http-out → 127.0.0.1:STUB    http-out → 127.0.0.1:STUB
#
# Round-trip proof (Rust→Go→stub→Go→Rust):
#   curl -x socks5://127.0.0.1:RM http://172.20.0.100:STUB/wg04b
#   Rust routes 172.20.0.100 → wg-rust (endpoint-as-outbound) → tunnel → Go
#   Go WG netstack receives 172.20.0.100:STUB, routes → http-out → stub
#   stub responds → Go → tunnel → Rust → curl (response traverses Go→Rust)
#
# The round-trip proves bidirectional WG tunnel:
#   - Request path: Rust → WG tunnel → Go (Rust initiates, Go receives)
#   - Response path: Go → WG tunnel → Rust (Go sends back, Rust receives)
#
# Limitation: a Go-initiated curl through WG to Rust is not possible because
# the Rust smoltcp netstack only supports outbound dial (no incoming TCP
# forwarder, unlike Go's gvisor SetTransportProtocolHandler). The round-trip
# response path already proves Go→Rust tunnel traversal.
#
# SOCKS5 proxy is used (not HTTP) because the Rust HTTP inbound hardcodes
# ip:None in RouteCtx, preventing ip_cidr rule matching. SOCKS5 with an
# IP-typed address populates ctx.ip, enabling ip_cidr route matching.
#
# Artifacts are written under WORK only; no repo-root scratch files.
set -u

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
GO_SRC="$REPO/go_fork_source/sing-box-1.13.13"
WORK="${WORK:-/tmp/pf04b-wg-live}"
SKIP_GO_BUILD="${SKIP_GO_BUILD:-0}"
SKIP_BUILD="${SKIP_BUILD:-0}"
KERNEL="${KERNEL:-$REPO/target/debug/app}"
GO_BIN="${GO_BIN:-$WORK/sing-box}"
HANDSHAKE_WAIT="${PF04B_HANDSHAKE_WAIT:-15}"

mkdir -p "$WORK"
RESULT="$WORK/result.json"
RUST_CONFIG="$WORK/rust_config.json"
GO_CONFIG="$WORK/go_config.json"
RUST_LOG="$WORK/rust.log"
GO_LOG="$WORK/go.log"
GO_BUILD_LOG="$WORK/go_build.log"
BUILD_LOG="$WORK/build.log"
STUB_LOG="$WORK/stub.log"
STUB_PORT_FILE="$WORK/stub.port"
KEYPAIR_FILE="$WORK/keypair.txt"
CURL_FWD_BODY="$WORK/curl_fwd.body"
CURL_FWD_ERR="$WORK/curl_fwd.err"
CURL_FWD_STATUS="$WORK/curl_fwd.status"

GO_BUILD_STATUS="not_run"
RUST_BUILD_STATUS="not_run"
GO_CONFIG_STATUS="not_run"
RUST_CONFIG_STATUS="not_run"
GO_STARTUP_STATUS="not_run"
RUST_STARTUP_STATUS="not_run"
GO_STARTED_SEEN="false"
RUST_STARTED_SEEN="false"
CURL_FWD_STATUS_VALUE=""
CURL_FWD_SUCCESS="false"
STUB_FWD_HIT="false"
GO_INBOUND_HIT="false"
RUST_OUTBOUND_HIT="false"
CLEANUP_STATUS="not_run"
MESSAGE=""
GO_PID=""
RUST_PID=""
STUB_PID=""

log() {
  printf '[pf04b] %s\n' "$*"
}

json_result() {
  local status="$1"
  local exit_code="$2"
  local message="$3"
  RESULT_STATUS="$status" \
  RESULT_EXIT="$exit_code" \
  RESULT_MESSAGE="$message" \
  PF04B_GO_BUILD_STATUS="$GO_BUILD_STATUS" \
  PF04B_RUST_BUILD_STATUS="$RUST_BUILD_STATUS" \
  PF04B_GO_CONFIG_STATUS="$GO_CONFIG_STATUS" \
  PF04B_RUST_CONFIG_STATUS="$RUST_CONFIG_STATUS" \
  PF04B_GO_STARTUP_STATUS="$GO_STARTUP_STATUS" \
  PF04B_RUST_STARTUP_STATUS="$RUST_STARTUP_STATUS" \
  PF04B_GO_STARTED_SEEN="$GO_STARTED_SEEN" \
  PF04B_RUST_STARTED_SEEN="$RUST_STARTED_SEEN" \
  PF04B_CURL_FWD_STATUS="$CURL_FWD_STATUS_VALUE" \
  PF04B_CURL_FWD_SUCCESS="$CURL_FWD_SUCCESS" \
  PF04B_STUB_FWD_HIT="$STUB_FWD_HIT" \
  PF04B_GO_INBOUND_HIT="$GO_INBOUND_HIT" \
  PF04B_RUST_OUTBOUND_HIT="$RUST_OUTBOUND_HIT" \
  PF04B_CLEANUP_STATUS="$CLEANUP_STATUS" \
  PF04B_WORK="$WORK" \
  python3 - <<'PY' > "$RESULT"
import json
import os

def bool_env(name):
    return os.environ.get(name, "").lower() == "true"

data = {
    "status": os.environ["RESULT_STATUS"],
    "exit_code": int(os.environ["RESULT_EXIT"]),
    "message": os.environ["RESULT_MESSAGE"],
    "work": os.environ["PF04B_WORK"],
    "stages": {
        "go_binary": os.environ["PF04B_GO_BUILD_STATUS"],
        "rust_binary": os.environ["PF04B_RUST_BUILD_STATUS"],
        "go_config_validation": os.environ["PF04B_GO_CONFIG_STATUS"],
        "rust_config_validation": os.environ["PF04B_RUST_CONFIG_STATUS"],
        "go_startup": os.environ["PF04B_GO_STARTUP_STATUS"],
        "rust_startup": os.environ["PF04B_RUST_STARTUP_STATUS"],
        "go_started_seen": bool_env("PF04B_GO_STARTED_SEEN"),
        "rust_started_seen": bool_env("PF04B_RUST_STARTED_SEEN"),
        "curl_round_trip_status": os.environ["PF04B_CURL_FWD_STATUS"],
        "curl_round_trip_success": bool_env("PF04B_CURL_FWD_SUCCESS"),
        "stub_hit": bool_env("PF04B_STUB_FWD_HIT"),
        "go_inbound_from_wg_hit": bool_env("PF04B_GO_INBOUND_HIT"),
        "rust_outbound_to_wg_hit": bool_env("PF04B_RUST_OUTBOUND_HIT"),
        "cleanup": os.environ["PF04B_CLEANUP_STATUS"],
    },
    "artifacts": {
        "go_config": "go_config.json",
        "rust_config": "rust_config.json",
        "go_log": "go.log",
        "rust_log": "rust.log",
        "go_build_log": "go_build.log",
        "build_log": "build.log",
        "stub_log": "stub.log",
        "keypair": "keypair.txt",
        "curl_fwd_body": "curl_fwd.body",
    },
}
print(json.dumps(data, indent=2, sort_keys=True))
PY
}

stop_process() {
  local pid="$1"
  if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
    kill -INT "$pid" 2>/dev/null || true
    for _ in $(seq 1 20); do
      kill -0 "$pid" 2>/dev/null || break
      sleep 0.25
    done
    if kill -0 "$pid" 2>/dev/null; then
      kill -TERM "$pid" 2>/dev/null || true
      sleep 0.5
    fi
    if kill -0 "$pid" 2>/dev/null; then
      kill -KILL "$pid" 2>/dev/null || true
    fi
  fi
}

stop_processes() {
  stop_process "$RUST_PID"
  stop_process "$GO_PID"
  stop_process "$STUB_PID"
}

evaluate_cleanup() {
  for pid in "$RUST_PID" "$GO_PID" "$STUB_PID"; do
    if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
      echo "failed_process_${pid}_still_running"
      return
    fi
  done
  echo "complete"
}

finish() {
  local status="$1"
  local code="$2"
  local message="$3"
  MESSAGE="$message"
  stop_processes
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

write_stub() {
  cat > "$WORK/stub.py" <<'PY'
import os
import socketserver
import sys

log_path = os.environ["PF04B_STUB_LOG"]
port_path = os.environ["PF04B_STUB_PORT_FILE"]

def log(line):
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(line.rstrip() + "\n")
        fh.flush()

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(10)
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
        body = b"WG04B-OK\n"
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

start_stub() {
  : > "$STUB_LOG"
  rm -f "$STUB_PORT_FILE"
  write_stub
  PF04B_STUB_LOG="$STUB_LOG" \
  PF04B_STUB_PORT_FILE="$STUB_PORT_FILE" \
  python3 "$WORK/stub.py" &
  STUB_PID=$!
  for _ in $(seq 1 50); do
    [ -s "$STUB_PORT_FILE" ] && return 0
    sleep 0.1
  done
  return 1
}

generate_keypairs() {
  # Generate two WireGuard keypairs; each invocation yields a matching
  # PrivateKey + PublicKey pair. Extract both from the SAME invocation.
  local rust_out go_out
  rust_out=$("$GO_BIN" generate wg-keypair 2>/dev/null)
  go_out=$("$GO_BIN" generate wg-keypair 2>/dev/null)
  RUST_PRIV=$(echo "$rust_out" | grep '^PrivateKey:' | cut -d' ' -f2)
  RUST_PUB=$(echo "$rust_out" | grep '^PublicKey:' | cut -d' ' -f2)
  GO_PRIV=$(echo "$go_out" | grep '^PrivateKey:' | cut -d' ' -f2)
  GO_PUB=$(echo "$go_out" | grep '^PublicKey:' | cut -d' ' -f2)

  if [ -z "$RUST_PRIV" ] || [ -z "$RUST_PUB" ] || [ -z "$GO_PRIV" ] || [ -z "$GO_PUB" ]; then
    return 1
  fi

  {
    echo "RUST_PRIV=$RUST_PRIV"
    echo "RUST_PUB=$RUST_PUB"
    echo "GO_PRIV=$GO_PRIV"
    echo "GO_PUB=$GO_PUB"
  } > "$KEYPAIR_FILE"
  return 0
}

alloc_port() {
  python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'
}

generate_configs() {
  local stub_port="$1"
  local rm_port="$2"
  local gm_port="$3"
  local w_port="$4"
  local r_port="$5"

  cat > "$RUST_CONFIG" <<EOF
{
  "log": { "level": "debug", "timestamp": false },
  "inbounds": [
    { "type": "mixed", "tag": "rust-mixed", "listen": "127.0.0.1", "listen_port": $rm_port }
  ],
  "endpoints": [
    {
      "type": "wireguard",
      "tag": "wg-rust",
      "address": ["10.0.0.2/32"],
      "private_key": "$RUST_PRIV",
      "listen_port": $r_port,
      "peers": [{
        "public_key": "$GO_PUB",
        "address": "127.0.0.1",
        "port": $w_port,
        "allowed_ips": ["0.0.0.0/0"],
        "persistent_keepalive_interval": 5
      }]
    }
  ],
  "outbounds": [
    { "type": "http", "tag": "http-out", "server": "127.0.0.1", "server_port": $stub_port },
    { "type": "direct", "tag": "direct" },
    { "type": "block", "tag": "block" }
  ],
  "route": {
    "rules": [
      { "ip_cidr": ["172.20.0.100/32"], "outbound": "wg-rust" }
    ],
    "final": "block"
  }
}
EOF

  cat > "$GO_CONFIG" <<EOF
{
  "log": { "level": "debug", "timestamp": false },
  "inbounds": [
    { "type": "mixed", "tag": "go-mixed", "listen": "127.0.0.1", "listen_port": $gm_port }
  ],
  "endpoints": [
    {
      "type": "wireguard",
      "tag": "wg-go",
      "address": ["10.0.0.1/32"],
      "private_key": "$GO_PRIV",
      "listen_port": $w_port,
      "peers": [{
        "public_key": "$RUST_PUB",
        "address": "127.0.0.1",
        "port": $r_port,
        "allowed_ips": ["0.0.0.0/0"],
        "persistent_keepalive_interval": 5
      }]
    }
  ],
  "outbounds": [
    { "type": "http", "tag": "http-out", "server": "127.0.0.1", "server_port": $stub_port },
    { "type": "direct", "tag": "direct" },
    { "type": "block", "tag": "block" }
  ],
  "route": {
    "rules": [
      { "ip_cidr": ["172.20.0.100/32"], "outbound": "http-out" }
    ],
    "final": "block"
  }
}
EOF
}

run_go_build() {
  if [ "$SKIP_GO_BUILD" = "1" ]; then
    if [ -x "$GO_BIN" ]; then
      GO_BUILD_STATUS="skipped_existing"
      return 0
    fi
    GO_BUILD_STATUS="skipped_missing_go_binary"
    return 1
  fi
  log "building Go sing-box"
  (cd "$GO_SRC" && go build -tags with_wireguard,with_gvisor -o "$GO_BIN" ./cmd/sing-box) > "$GO_BUILD_LOG" 2>&1
  local rc=$?
  if [ "$rc" -eq 0 ] && [ -x "$GO_BIN" ]; then
    GO_BUILD_STATUS="pass"
    return 0
  fi
  GO_BUILD_STATUS="fail"
  return "$rc"
}

run_rust_build() {
  if [ "$SKIP_BUILD" = "1" ]; then
    if [ -x "$KERNEL" ]; then
      RUST_BUILD_STATUS="skipped_existing"
      return 0
    fi
    RUST_BUILD_STATUS="skipped_missing_kernel"
    return 1
  fi
  log "building Rust app"
  (cd "$REPO" && cargo build -p app --bin app --features adapters,clash_api) > "$BUILD_LOG" 2>&1
  local rc=$?
  if [ "$rc" -eq 0 ] && [ -x "$KERNEL" ]; then
    RUST_BUILD_STATUS="pass"
    return 0
  fi
  RUST_BUILD_STATUS="fail"
  return "$rc"
}

wait_for_log() {
  local pattern="$1"
  local logfile="$2"
  local timeout_steps="$3"
  for _ in $(seq 1 "$timeout_steps"); do
    if grep -q "$pattern" "$logfile" 2>/dev/null; then
      return 0
    fi
    sleep 0.25
  done
  return 1
}

run_go_config_check() {
  log "validating Go config"
  "$GO_BIN" check -c "$GO_CONFIG" > "$WORK/go_check.log" 2>&1
  local rc=$?
  if [ "$rc" -eq 0 ]; then
    GO_CONFIG_STATUS="pass"
    return 0
  fi
  GO_CONFIG_STATUS="fail"
  return "$rc"
}

run_rust_config_check() {
  log "validating Rust config"
  "$KERNEL" check --disable-color -c "$RUST_CONFIG" --schema-v2-validate > "$WORK/rust_check.log" 2>&1
  local rc=$?
  if [ "$rc" -eq 0 ] || grep -q "Config validation passed" "$WORK/rust_check.log" 2>/dev/null; then
    RUST_CONFIG_STATUS="pass"
    return 0
  fi
  RUST_CONFIG_STATUS="fail"
  return "$rc"
}

start_go() {
  log "starting Go sing-box"
  "$GO_BIN" run -c "$GO_CONFIG" -D "$WORK" > "$GO_LOG" 2>&1 &
  GO_PID=$!
  if ! wait_for_log "started" "$GO_LOG" 80; then
    GO_STARTUP_STATUS="failed_before_started"
    finish "FAIL" 1 "Go sing-box did not reach started state"
  fi
  GO_STARTUP_STATUS="started"
  GO_STARTED_SEEN="true"
}

start_rust() {
  log "starting Rust app"
  "$KERNEL" run --disable-color -c "$RUST_CONFIG" -D "$WORK" > "$RUST_LOG" 2>&1 &
  RUST_PID=$!
  if ! wait_for_log "sing-box started" "$RUST_LOG" 80; then
    RUST_STARTUP_STATUS="failed_before_started"
    finish "FAIL" 1 "Rust app did not reach 'sing-box started'"
  fi
  RUST_STARTUP_STATUS="started"
  RUST_STARTED_SEEN="true"
}

run_forward_curl() {
  log "round-trip curl (Rust→Go→stub→Go→Rust): http://172.20.0.100:$STUB_PORT/wg04b via socks5://$RM_PORT"
  # Use SOCKS5 (not HTTP) proxy so the destination IP is sent as an IP-typed
  # SOCKS5 address. The HTTP inbound path hardcodes ip:None in RouteCtx, so
  # ip_cidr rules never match. SOCKS5 with an IP-typed address populates
  # ctx.ip, enabling ip_cidr route matching.
  CURL_FWD_STATUS_VALUE="$(curl -x "socks5://127.0.0.1:$RM_PORT" -sS -o "$CURL_FWD_BODY" -w "%{http_code}" --max-time 30 "http://172.20.0.100:$STUB_PORT/wg04b" 2> "$CURL_FWD_ERR" || true)"
  printf '%s\n' "$CURL_FWD_STATUS_VALUE" > "$CURL_FWD_STATUS"
  if [ "$CURL_FWD_STATUS_VALUE" = "200" ] && grep -q "WG04B-OK" "$CURL_FWD_BODY" 2>/dev/null; then
    CURL_FWD_SUCCESS="true"
  fi
  if grep -q "CONNECT_LINE CONNECT 172.20.0.100:$STUB_PORT" "$STUB_LOG" 2>/dev/null; then
    STUB_FWD_HIT="true"
  fi
  # Go log: proves traffic arrived from WG tunnel and was routed to http-out
  if grep -q "inbound connection to 172.20.0.100:$STUB_PORT" "$GO_LOG" 2>/dev/null; then
    GO_INBOUND_HIT="true"
  fi
  # Rust log: proves Rust sent traffic through WG endpoint outbound
  if grep -q "outbound TCP connection to 172.20.0.100:$STUB_PORT" "$RUST_LOG" 2>/dev/null; then
    RUST_OUTBOUND_HIT="true"
  fi
}

# ── main ────────────────────────────────────────────────────────────────
log "repo=$REPO"
log "work=$WORK"
rm -f "$RUST_LOG" "$GO_LOG" "$STUB_LOG" "$STUB_PORT_FILE" "$RESULT" \
      "$CURL_FWD_BODY" "$CURL_FWD_ERR" "$CURL_FWD_STATUS"

if ! run_go_build; then
  finish "FAIL" 1 "Go sing-box build failed"
fi

if ! run_rust_build; then
  finish "FAIL" 1 "Rust app build failed"
fi

log "generating WireGuard keypairs"
if ! generate_keypairs; then
  finish "FAIL" 1 "WireGuard keypair generation failed"
fi

if ! start_stub; then
  finish "FAIL" 1 "failed to start local HTTP CONNECT stub"
fi
STUB_PORT="$(cat "$STUB_PORT_FILE")"
log "stub listening on 127.0.0.1:$STUB_PORT"

RM_PORT="$(alloc_port)"
GM_PORT="$(alloc_port)"
W_PORT="$(alloc_port)"
R_PORT="$(alloc_port)"
log "ports: rust_mixed=$RM_PORT go_mixed=$GM_PORT go_wg=$W_PORT rust_wg=$R_PORT"

generate_configs "$STUB_PORT" "$RM_PORT" "$GM_PORT" "$W_PORT" "$R_PORT"

if ! run_go_config_check; then
  finish "FAIL" 1 "Go config validation failed"
fi

if ! run_rust_config_check; then
  finish "FAIL" 1 "Rust config validation failed"
fi

start_go
start_rust

log "waiting ${HANDSHAKE_WAIT}s for WireGuard handshake to settle"
sleep "$HANDSHAKE_WAIT"

run_forward_curl

local_roundtrip_ok="false"
if [ "$CURL_FWD_SUCCESS" = "true" ] && [ "$STUB_FWD_HIT" = "true" ] && \
   [ "$GO_INBOUND_HIT" = "true" ] && [ "$RUST_OUTBOUND_HIT" = "true" ]; then
  local_roundtrip_ok="true"
fi

if [ "$local_roundtrip_ok" = "true" ]; then
  finish "PASS" 0 "WireGuard live round-trip proof PASS: Rust→Go (request via WG tunnel) → stub → Go→Rust (response via WG tunnel); all four assertions green (curl 200 + body + stub CONNECT + Go inbound + Rust outbound)"
fi

finish "FAIL" 1 "WireGuard live proof failed (roundtrip=$local_roundtrip_ok; curl=$CURL_FWD_STATUS_VALUE stub=$STUB_FWD_HIT go_in=$GO_INBOUND_HIT rust_out=$RUST_OUTBOUND_HIT)"
