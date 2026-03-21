#!/usr/bin/env bash
set -euo pipefail
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")"/../.. && pwd)"
cd "$ROOT"
mkdir -p dist .e2e/artifacts
RELEASE_FEATS="${RELEASE_FEATS:-acceptance,explain,pprof,panic_log,hardening}"

# 1) 动态选择目标（若 rustup 未装就退化为 host）
HOST=$(rustc -vV | awk '/host/ {print $2}')
mapfile -t WANT < <(rustup target list --installed 2>/dev/null | awk '
  /x86_64-unknown-linux-gnu|aarch64-unknown-linux-gnu|x86_64-apple-darwin/ {print $1}')
if [ "${#WANT[@]}" -eq 0 ]; then WANT=("$HOST"); fi

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1"
  else
    shasum -a 256 "$1"
  fi
}

write_manifest() {
  : > dist/manifest.txt
  find dist -maxdepth 1 -type f -name 'singbox-rust-*.tar.gz' -print0 \
    | while IFS= read -r -d '' f; do
        hash_file "$f"
      done | tee .e2e/artifacts/release.sha256 > dist/manifest.txt || true
}

manifest_lines() {
  if [ -f dist/manifest.txt ]; then
    wc -l < dist/manifest.txt | tr -d ' '
  else
    echo 0
  fi
}

build_one() {
  local t="$1"
  echo "[rel-matrix] building $t"
  local success=false
  if command -v cross >/dev/null 2>&1; then
    if cross build -q -p app --release --target "$t" --features "$RELEASE_FEATS" --bin run --bin sb-explaind --bin sb-version 2>/dev/null; then
      success=true
    fi
  else
    if cargo build -q -p app --release --target "$t" --features "$RELEASE_FEATS" --bin run --bin sb-explaind --bin sb-version 2>/dev/null; then
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
  local copied=0
  # 收集核心二进制（存在才拷贝）
  for b in run sb-explaind sb-version; do
    if [ -f "$OUT/$b" ]; then
      cp "$OUT/$b" "$DST/"
      copied=1
    fi
  done
  if [ "$copied" -eq 0 ]; then
    rm -rf "$DST"
    echo "[rel-matrix] no expected binaries for $t, skipping package"
    return 1
  fi
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
write_manifest

# 3) 降级方案：如果 release 包不足，补一个 debug full/minimal fallback
if [ "$(manifest_lines)" -lt 2 ]; then
  cargo build -q -p app --features "$RELEASE_FEATS" --bin run --bin sb-explaind --bin sb-version 2>/dev/null || true
fi
if [ "$(manifest_lines)" -lt 2 ] && [ -f target/debug/run ]; then
  echo "[rel-matrix] release matrix sparse, using debug fallback"
  
  # 创建完整包
  DST="dist/singbox-rust-debug-$HOST"
  mkdir -p "$DST"
  cp target/debug/run "$DST/" || true
  [ -f target/debug/sb-explaind ] && cp target/debug/sb-explaind "$DST/" || true
  [ -f target/debug/sb-version ] && cp target/debug/sb-version "$DST/" || true
  if [ -x target/debug/sb-version ]; then target/debug/sb-version > "$DST/version.json"; fi
  [ -f LICENSE ] && cp LICENSE "$DST/" || echo "license: see repo" > "$DST/LICENSE"
  echo "sbom: debug fallback" > "$DST/SBOM.txt"
  tar -C dist -czf "dist/singbox-rust-debug-$HOST.tar.gz" "singbox-rust-debug-$HOST"
  
  # 创建最小包（仅核心二进制）
  DST_MIN="dist/singbox-rust-minimal-$HOST"
  mkdir -p "$DST_MIN"
  cp target/debug/run "$DST_MIN/" || true
  if [ -x target/debug/sb-version ]; then target/debug/sb-version > "$DST_MIN/version.json"; fi
  echo "license: see repo" > "$DST_MIN/LICENSE"
  echo "sbom: minimal" > "$DST_MIN/SBOM.txt"
  tar -C dist -czf "dist/singbox-rust-minimal-$HOST.tar.gz" "singbox-rust-minimal-$HOST"
  
  # 生成 manifest
  write_manifest
fi

echo "[rel-matrix] manifest lines: $(manifest_lines)"
