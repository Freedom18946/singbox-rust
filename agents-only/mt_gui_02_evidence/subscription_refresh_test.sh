#!/usr/bin/env bash
# subscription_refresh_test.sh -- exercise a GUI-style subscription/remote-config
# refresh path against mock_public_infra's /sub/clash.json endpoint, including
# auth, caching (ETag / If-None-Match), and consumption by both kernels via
# their `check` subcommand.
set -u
set -o pipefail

MOCK_HTTP="http://127.0.0.1:18080"
SUB_URL="$MOCK_HTTP/sub/clash.json"
SUB_BEARER="mt-gui-02-sub-bearer"
REPO="/Users/bob/Desktop/Projects/ING/sing/singbox-rust"
RUST_BIN="$REPO/target/release/app"
GO_BIN="$REPO/go_fork_source/sing-box-1.12.14/sing-box"

echo "=== MT-GUI-02 subscription refresh simulation ==="
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "Mock: $MOCK_HTTP"
echo

# S1 - public fetch (no auth)
echo "--- S1: GET /sub/clash.json (no auth) ---"
curl -s -D - -o /tmp/mt_gui_02_sub_body.json -w 'status=%{http_code} bytes=%{size_download}\n' "$SUB_URL" | head -15
echo

# S2 - wrong Bearer
echo "--- S2: GET /sub/clash.json (wrong Bearer) ---"
curl -s -o /dev/null -w 'status=%{http_code}\n' -H 'Authorization: Bearer wrong' "$SUB_URL"
echo

# S3 - correct Bearer, capture ETag
echo "--- S3: GET /sub/clash.json (correct Bearer) ---"
curl -s -D /tmp/mt_gui_02_sub_hdr.txt -o /tmp/mt_gui_02_sub_body.json -w 'status=%{http_code}\n' \
  -H "Authorization: Bearer $SUB_BEARER" "$SUB_URL"
ETAG=$(awk -F': ' 'tolower($1)=="etag"{print $2}' /tmp/mt_gui_02_sub_hdr.txt | tr -d '\r')
CC=$(awk -F': ' 'tolower($1)=="cache-control"{print $2}' /tmp/mt_gui_02_sub_hdr.txt | tr -d '\r')
BYTES=$(wc -c </tmp/mt_gui_02_sub_body.json | tr -d ' ')
echo "etag=$ETAG cache-control=$CC bytes=$BYTES"
echo

# S4 - If-None-Match 304
echo "--- S4: GET /sub/clash.json (correct auth + If-None-Match) ---"
curl -s -o /dev/null -w 'status=%{http_code}\n' \
  -H "Authorization: Bearer $SUB_BEARER" \
  -H "If-None-Match: $ETAG" "$SUB_URL"
echo

# S5 - use downloaded body as a config and run `check` on both kernels.
# This is a stand-in for "GUI fetches a remote profile and hands it to the kernel".
echo "--- S5: feed returned sub body into both kernels via 'check' ---"
RUST_CFG=$(mktemp -t mt_gui_02_sub_rust.XXXXXX.json)
GO_CFG=$(mktemp -t mt_gui_02_sub_go.XXXXXX.json)
# The returned blob is GUI/singbox-shape. We wrap it into a minimal runnable
# config per kernel: add an experimental.clash_api + one socks inbound on a
# throwaway port so `check` can validate parsing, and inject direct fallback.
python3 - "$RUST_CFG" "$GO_CFG" <<'PYEOF'
import json, sys, copy
sub = json.load(open("/tmp/mt_gui_02_sub_body.json"))
def mkbase():
    return {
        "log": copy.deepcopy(sub.get("log", {"level": "warn"})),
        "experimental": {"clash_api": {"external_controller": "127.0.0.1:29090", "secret": "test"}},
        "inbounds": [],
        "outbounds": copy.deepcopy(sub.get("outbounds", [{"type":"direct","tag":"direct"}])),
        "route": copy.deepcopy(sub.get("route", {"rules": [], "final": "direct"})),
    }
rust = mkbase()
rust["inbounds"] = [{"type":"socks","name":"socks-in","listen":"127.0.0.1","port":21810}]
# Rust expects outbound identity under `name`; the returned body uses Go-style `tag`.
for ob in rust["outbounds"]:
    if "tag" in ob and "name" not in ob:
        ob["name"] = ob.pop("tag")
open(sys.argv[1],"w").write(json.dumps(rust))
go = mkbase()
go["inbounds"] = [{"type":"socks","tag":"socks-in","listen":"127.0.0.1","listen_port":21811}]
# Go keeps `tag`; strip any accidental `name` keys (defensive).
for ob in go["outbounds"]:
    if "name" in ob and "tag" not in ob:
        ob["tag"] = ob.pop("name")
open(sys.argv[2],"w").write(json.dumps(go))
PYEOF

echo "--- Rust check ---"
"$RUST_BIN" check -c "$RUST_CFG" 2>&1 | tail -n 20
echo "rust exit=${PIPESTATUS[0]}"
echo

echo "--- Go check ---"
"$GO_BIN" check -c "$GO_CFG" 2>&1 | tail -n 20
echo "go exit=${PIPESTATUS[0]}"
echo

rm -f "$RUST_CFG" "$GO_CFG" /tmp/mt_gui_02_sub_body.json /tmp/mt_gui_02_sub_hdr.txt
echo "=== subscription refresh done ==="
