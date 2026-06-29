#!/usr/bin/env bash
# extra_shape_probe.sh -- dump raw bodies for endpoints whose shape already
# differs between the two kernels, so we have the literal bytes on record.
set -u
set -o pipefail

RUST_API="http://127.0.0.1:19090"
GO_API="http://127.0.0.1:9090"
AUTH=( -H "Authorization: Bearer test-secret" )

echo "=== MT-GUI-02 supplementary body-shape probe ==="
echo "Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo

for ep in "/rules" "/providers/proxies" "/providers/rules" \
          "/dns/query?name=mock-public.local&type=A" \
          "/dns/query?name=example.com&type=A" \
          "/configs" "/connections"; do
  echo "--- $ep raw body ---"
  echo "Rust:"
  curl -s "${AUTH[@]}" "$RUST_API$ep" | python3 -m json.tool 2>/dev/null || \
    curl -s "${AUTH[@]}" "$RUST_API$ep"
  echo
  echo "Go:"
  curl -s "${AUTH[@]}" "$GO_API$ep" | python3 -m json.tool 2>/dev/null || \
    curl -s "${AUTH[@]}" "$GO_API$ep"
  echo
  echo
done

echo "=== probe done ==="
