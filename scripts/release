#!/usr/bin/env bash
set -euo pipefail
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")"/.. && pwd)"
cd "$ROOT"
need(){ command -v "$1" >/dev/null 2>&1; }
OUT="${OUT:-target/rc}"
mkdir -p "$OUT"/{bin,snapshots,sbom,license,manifest}
export RUSTFLAGS="${RUSTFLAGS:-} -C link-arg=-s"
export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(date +%s)}"
cargo build --profile release --locked
cp target/release/singbox-rust "$OUT/bin/"
if [ -x target/release/sb-version ]; then cp target/release/sb-version "$OUT/bin/"; fi
# 版本 & 指纹
"$OUT/bin/sb-version" > "$OUT/manifest/sb-version.json" || true
sha256sum "$OUT/bin/"* | awk '{print $1"  " $2}' > "$OUT/manifest/sha256.txt"
# SBOM / 许可证
if need cargo-cyclonedx; then cargo cyclonedx --format json -o "$OUT/sbom/sbom.json"; fi
if need cargo-deny; then cargo deny check licenses -L error && touch "$OUT/license/deny.ok" || touch "$OUT/license/deny.fail"; fi
# 打包
tar czf "$OUT/rc-$(date +%Y%m%d-%H%M%S).tar.gz" -C "$OUT" .
echo "[release] done -> $OUT"