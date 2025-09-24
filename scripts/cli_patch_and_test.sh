#!/usr/bin/env bash
set -Eeuo pipefail
info(){ echo "[INFO] $*"; }; ok(){ echo "[OK] $*"; }; err(){ echo "[ERR] $*" >&2; }
ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"; cd "$ROOT"

want(){ command -v "$1" >/dev/null 2>&1 || { err "missing $1"; exit 127; }; }
want git; want perl; want python3; want cargo

OUTDIR=".e2e"; mkdir -p "$OUTDIR"

# 1) config.yaml 动态端口（:0）
CFG="config.yaml"
if [[ -f "$CFG" ]]; then
  info "patch $CFG -> listen :0 (http/socks/metrics)"
  perl -0777 -pe 's/(listen:\s*127\.0\.0\.1:)\d+/${1}0/g' -i "$CFG"
  perl -0777 -pe 's/(metrics[^\n]*?\n(?:[ \t]+)listen:\s*127\.0\.0\.1:)\d+/${1}0/g' -i "$CFG" || true
else
  err "missing $CFG (skip)"; fi

# 2) 生成补丁（把改动固化）
git add -A
git commit -m "bundle: http accept heartbeat + 405 respond seq + scripts + dynamic ports" >/dev/null || true
mkdir -p out
git diff -p HEAD~1 HEAD > out/http-405-bundle.patch || git show HEAD > out/http-405-bundle.patch
ok "patch generated at out/http-405-bundle.patch"

# 3) 编译
info "cargo build"
cargo build -q --features "http,socks,metrics" --bin singbox-rust || { err "build failed"; exit 2; }

# 4) 清理残留并跑 run_and_test.zsh
info "kill leftovers and run script"
pkill -f singbox-rust >/dev/null 2>&1 || true
sleep 1
for p in 18081 11080 9900; do
  lsof -nP -iTCP:$p -sTCP:LISTEN -t 2>/dev/null | xargs -I{} kill -9 {} 2>/dev/null || true
done

chmod +x scripts/run_and_test.zsh || true
set +e
scripts/run_and_test.zsh
RC=$?
set -e
if [[ $RC -ne 0 ]]; then
  err "run_and_test failed with $RC"
  tail -n 120 .e2e/sing.log || true
  exit $RC
fi

# 5) 解析端口，确认三就绪
HTTP_ACTUAL=$(grep -E "HTTP CONNECT bound .* actual=127\.0\.0\.1:[0-9]+" .e2e/sing.log | tail -n1 | sed -E 's/.*actual=127\.0\.0\.1:([0-9]+).*/\1/')
SOCKS_ACTUAL=$(grep -E "SOCKS5 bound .* actual=127\.0\.0\.1:[0-9]+" .e2e/sing.log | tail -n1 | sed -E 's/.*actual=127\.0\.0\.1:([0-9]+).*/\1/')
[[ -z "${HTTP_ACTUAL}" || -z "${SOCKS_ACTUAL}" ]] && { err "cannot resolve actual ports"; exit 3; }
ok "resolved HTTP=127.0.0.1:${HTTP_ACTUAL} SOCKS=127.0.0.1:${SOCKS_ACTUAL}"

# 6) 启动临时实例，做 10 连发（避免打断主实例与脚本内部的 curl/探针）
info "spawn ephemeral instance for multi-probe"
pkill -f singbox-rust >/dev/null 2>&1 || true
SB_HTTP_DISABLE_STOP=1 RUST_LOG=info ./target/debug/singbox-rust --config ./config.yaml > .e2e/sing.multi.log 2>&1 &
EPH_PID=$!
trap 'kill -9 $EPH_PID >/dev/null 2>&1 || true' EXIT

deadline=$(( $(date +%s) + 8 ))
HTTP_MULTI=""
while [[ $(date +%s) -lt $deadline ]]; do
  HTTP_MULTI=$(grep -E "HTTP CONNECT bound .* actual=127\.0\.0\.1:[0-9]+" .e2e/sing.multi.log | tail -n1 | sed -E 's/.*actual=127\.0\.0\.1:([0-9]+).*/\1/')
  [[ -n "$HTTP_MULTI" ]] && break
  sleep 0.2
done
[[ -z "$HTTP_MULTI" ]] && { err "cannot resolve HTTP port from .e2e/sing.multi.log"; tail -n 80 .e2e/sing.multi.log || true; exit 4; }

python3 scripts/probe_http_multi.py "127.0.0.1:${HTTP_MULTI}" 10 || { err "multi probe not all 405"; exit 5; }

# 收尾
kill -9 $EPH_PID >/dev/null 2>&1 || true
ok "ALL DONE"
