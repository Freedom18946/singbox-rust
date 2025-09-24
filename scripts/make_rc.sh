#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export RUST_BACKTRACE=1

changed="$(git status --porcelain || true)"

echo "[1/5] build release bins..."
cargo build --release --bins

echo "[2/5] collect version info..."
ver_json="$(target/release/version || target/debug/version)"
name="$(jq -r .name <<<"$ver_json")"
ver="$(jq -r .version <<<"$ver_json")"
dist="dist/${name}-${ver}"
mkdir -p "$dist"
echo "$ver_json" > "$dist/version-${name}.json"

echo "[3/5] stage artifacts..."
cp -f target/release/{app,run,version} "$dist/" 2>/dev/null || true
cp -f target/debug/{app,run,version} "$dist/" 2>/dev/null || true

echo "[4/5] manifest with sha256..."
pushd "$dist" >/dev/null
rm -f RC_MANIFEST.txt
for f in *; do
  if [ -f "$f" ]; then
    sha256sum "$f" >> RC_MANIFEST.txt
  fi
done
popd >/dev/null

echo "[5/5] summary json..."
cat <<EOF
{
  "task": "make_rc",
  "git_status": $(jq -Rs . <<<"$changed"),
  "dist": "$dist",
  "files": $(ls -1 "$dist" | jq -R . | jq -s .),
  "version": $ver_json
}
EOF