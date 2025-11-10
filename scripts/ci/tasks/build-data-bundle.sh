#!/usr/bin/env bash
set -euo pipefail

# CI task to build rule/data bundle.
#
# Steps:
# 1) Build CLI with router+explain features (rule-set compile requires router)
# 2) Compile JSON rule-sets in ./rules to ./out
# 3) Download GeoIP/Geosite databases to ./data
# 4) Create data bundle tar.gz in ./bundle and emit artifact path
#
# Environment (optional):
#   BIN_FEATURES   (default: router,explain)
#   GEOIP_URL      (override sing-geoip release URL)
#   GEOSITE_URL    (override sing-geosite release URL)
#   GEOIP_SHA256   (optional checksum)
#   GEOSITE_SHA256 (optional checksum)

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$ROOT"

: "${BIN_FEATURES:=router,explain}"

echo "[1/4] Building CLI (features: $BIN_FEATURES)"
cargo build --features "$BIN_FEATURES" -q

echo "[2/4] Compiling rule-sets (if any)"
mkdir -p out
if compgen -G "rules/*.json" > /dev/null; then
  scripts/tools/compile-rulesets.sh --in rules --out out --bin target/debug/app
else
  echo "No rules/*.json found; skipping compile"
fi

echo "[3/4] Fetching geodata"
mkdir -p data
ARGS=(--dest ./data)
[[ -n "${GEOIP_URL:-}" ]] && ARGS+=(--geoip-url "$GEOIP_URL")
[[ -n "${GEOSITE_URL:-}" ]] && ARGS+=(--geosite-url "$GEOSITE_URL")
[[ -n "${GEOIP_SHA256:-}" ]] && ARGS+=(--geoip-sha256 "$GEOIP_SHA256")
[[ -n "${GEOSITE_SHA256:-}" ]] && ARGS+=(--geosite-sha256 "$GEOSITE_SHA256")
scripts/tools/update-geodata.sh "${ARGS[@]}"

echo "[4/4] Bundling"
mkdir -p bundle
scripts/tools/make-data-bundle.sh --data ./data --rules ./out --out ./bundle

# Emit manifest for CI provenance
scripts/tools/gen-data-manifest.sh --data ./data --rules ./out --out ./bundle --format both

echo "ARTIFACT_DIR=bundle" >> "$GITHUB_ENV" 2>/dev/null || true
echo "[✓] Done. See ./bundle for artifacts"
