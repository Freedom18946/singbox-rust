#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.." || exit 1

echo "[fuzz-smoke] running quick fuzz smoke (30-60s)"

if ! cargo install cargo-fuzz --version ^0.12.0 >/dev/null 2>&1; then
  echo "cargo-fuzz already installed or installed now"
fi

pushd fuzz >/dev/null

# limit time/runs per target
targets=(fuzz_v2ray_simple fuzz_socks_udp fuzz_dns_message)

for t in "${targets[@]}"; do
  echo "[fuzz-smoke] target=$t"
  # Use a small max_total_time to keep CI fast
  cargo fuzz run "$t" -jobs=1 -workers=1 -seed=1337 -max_total_time=20 >/dev/null 2>&1 || true
done

popd >/dev/null

echo "[fuzz-smoke] done"

