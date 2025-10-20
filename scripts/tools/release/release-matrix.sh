#!/usr/bin/env bash
set -euo pipefail
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")"/.. && pwd)"
cd "$ROOT"
mkdir -p dist .e2e

# 1) 动态选择目标（若 rustup 未装就退化为 host）
HOST=$(rustc -vV | awk '/host/ {print $2}')
mapfile -t WANT < <(rustup target list --installed 2>/dev/null | awk '
  /x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu|x86_64-apple-darwin/ {print $1}')
if [ "${#WANT[@]}" -eq 0 ]; then WANT=("$HOST"); fi

build_one() {
  local t="$1"
  echo "[rel-matrix] building $t"
  local success=false
  if command -v cross >/dev/null 2>&1; then
    if cross build --release --target "$t" 2>/dev/null; then
      success=true
    fi
  else
    if cargo build --release --target "$t" 2>/dev/null; then
      success=true
    fi
  fi
  
  if [ "$success" = false ]; then
    echo "[rel-matrix] failed to build $t, skipping"
    return 1
  fi
  
  local OUT="target/$t/release"
  local DST="dist/singbox-rust-$t"
  mkdir -p "$DST"
  # 收集核心二进制（存在才拷贝）
  for b in singbox-rust sb-explaind sb-version; do
    [ -f "$OUT/$b" ] && cp "$OUT/$b" "$DST/" || true
  done
  # 版本宣告
  if [ -x "$OUT/sb-version" ]; then "$OUT/sb-version" > "$DST/version.json"; fi
  # 许可证/SBOM（占位）
  [ -f LICENSE ] && cp LICENSE "$DST/" || echo "license: see repo" > "$DST/LICENSE"
  echo "sbom: optional" > "$DST/SBOM.txt"
  # 压缩包
  tar -C dist -czf "dist/singbox-rust-$t.tar.gz" "singbox-rust-$t"
}

for t in "${WANT[@]}"; do build_one "$t" || true; done

# 2) 生成 manifest（sha256 sum）
find dist -maxdepth 1 -type f -name 'singbox-rust-*.tar.gz' -print0 \
 | xargs -0 sha256sum 2>/dev/null | tee .e2e/artifacts/release.sha256 > dist/manifest.txt || true

# 3) 降级方案：如果没有任何 release 包，用 debug 构建
if [ ! -s dist/manifest.txt ] && [ -f target/debug/singbox-rust ]; then
  echo "[rel-matrix] no release builds, using debug fallback"
  
  # 创建完整包
  DST="dist/singbox-rust-debug-$HOST"
  mkdir -p "$DST"
  cp target/debug/singbox-rust "$DST/" || true
  [ -f target/debug/sb-explaind ] && cp target/debug/sb-explaind "$DST/" || true
  [ -f target/debug/sb-version ] && cp target/debug/sb-version "$DST/" || true
  if [ -x target/debug/sb-version ]; then target/debug/sb-version > "$DST/version.json"; fi
  [ -f LICENSE ] && cp LICENSE "$DST/" || echo "license: see repo" > "$DST/LICENSE"
  echo "sbom: debug fallback" > "$DST/SBOM.txt"
  tar -C dist -czf "dist/singbox-rust-debug-$HOST.tar.gz" "singbox-rust-debug-$HOST"
  
  # 创建最小包（仅核心二进制）
  DST_MIN="dist/singbox-rust-minimal-$HOST"
  mkdir -p "$DST_MIN"
  cp target/debug/singbox-rust "$DST_MIN/" || true
  if [ -x target/debug/sb-version ]; then target/debug/sb-version > "$DST_MIN/version.json"; fi
  echo "license: see repo" > "$DST_MIN/LICENSE"
  echo "sbom: minimal" > "$DST_MIN/SBOM.txt"
  tar -C dist -czf "dist/singbox-rust-minimal-$HOST.tar.gz" "singbox-rust-minimal-$HOST"
  
  # 生成 manifest
  find dist -maxdepth 1 -name "singbox-rust-*-$HOST.tar.gz" -exec sha256sum {} \; | tee .e2e/artifacts/release.sha256 > dist/manifest.txt
fi

echo "[rel-matrix] manifest lines: $(wc -l < dist/manifest.txt 2>/dev/null || echo 0)"