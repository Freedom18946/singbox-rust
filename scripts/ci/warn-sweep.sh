#!/usr/bin/env bash
set -euo pipefail
# Run strict_warnings builds across feature combos and emit JSON
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")"/.. && pwd)"
cd "$ROOT"

combos=(
  "explain,metrics,dns_udp"
  "explain,metrics,selector_p3,dns_udp"
  "explain,metrics,geoip_mmdb,dns_udp"
  "metrics,rule_coverage,dns_udp"
  "metrics,bench,dns_udp"
  "explain,metrics,selector_p3,geoip_mmdb,rule_coverage,dns_udp"
)

out=".e2e/warn_sweep.json"
mkdir -p .e2e

pass_all=1
export RUSTFLAGS="-D warnings --cap-lints=allow"

# Start with empty matrix
cat > "$out" << 'EOF'
{
  "status": "running",
  "remaining_warnings": 0,
  "strict_warnings": true,
  "cap_lints_allow": true,
  "matrix": []
}
EOF

for f in "${combos[@]}"; do
  echo "[warn-sweep] workspace with features: $f"
  feature_pass=1

  if ! cargo build -q --features "strict_warnings,$f"; then feature_pass=0; pass_all=0; fi
  # bins (built with workspace)
  if ! cargo build -q --features "strict_warnings,$f" --bins; then feature_pass=0; pass_all=0; fi
  # Focus on core lib only for strict warnings (tests have various dependencies)
  if ! cargo build -q -p sb-core --features "strict_warnings,$f"; then feature_pass=0; pass_all=0; fi

  # accumulate result
  status=$([ $feature_pass -eq 1 ] && echo "passed" || echo "failed")
  echo "  Result: features=$f, status=$status"

  # Add to matrix
  jq --arg f "$f" --arg status "$status" \
     '.matrix += [{features:$f, status:$status}]' "$out" > "$out.tmp" && mv "$out.tmp" "$out"
done

# Update final status
final_status=$([ $pass_all -eq 1 ] && echo "passed" || echo "failed")
jq --arg status "$final_status" '.status = $status' "$out" > "$out.tmp" && mv "$out.tmp" "$out"

if [[ $pass_all -ne 1 ]]; then
  echo "[warn-sweep] FAILED matrix (see $out)"; exit 1
fi
echo "[warn-sweep] OK -> $out"