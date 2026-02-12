#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  package_release.sh \
    --version <version> \
    --target <target-triple> \
    --os <os-name> \
    --arch <arch-name> \
    --binary <binary-path> \
    --out-dir <output-dir> \
    --config-template <config-template.json> \
    --readme <README.md> \
    [--archive tar.gz|zip]
EOF
}

VERSION=""
TARGET=""
OS_NAME=""
ARCH=""
BINARY=""
OUT_DIR=""
ARCHIVE="tar.gz"
CONFIG_TEMPLATE=""
README_PATH=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --target) TARGET="$2"; shift 2 ;;
    --os) OS_NAME="$2"; shift 2 ;;
    --arch) ARCH="$2"; shift 2 ;;
    --binary) BINARY="$2"; shift 2 ;;
    --out-dir) OUT_DIR="$2"; shift 2 ;;
    --archive) ARCHIVE="$2"; shift 2 ;;
    --config-template) CONFIG_TEMPLATE="$2"; shift 2 ;;
    --readme) README_PATH="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *)
      echo "unknown argument: $1" >&2
      usage
      exit 2
      ;;
  esac
done

if [[ -z "$VERSION" || -z "$TARGET" || -z "$OS_NAME" || -z "$ARCH" || -z "$BINARY" || -z "$OUT_DIR" || -z "$CONFIG_TEMPLATE" || -z "$README_PATH" ]]; then
  echo "missing required arguments" >&2
  usage
  exit 2
fi

if [[ "$ARCHIVE" != "tar.gz" && "$ARCHIVE" != "zip" ]]; then
  echo "--archive must be tar.gz or zip" >&2
  exit 2
fi

if [[ ! -f "$BINARY" ]]; then
  echo "binary not found: $BINARY" >&2
  exit 1
fi
if [[ ! -f "$CONFIG_TEMPLATE" ]]; then
  echo "config template not found: $CONFIG_TEMPLATE" >&2
  exit 1
fi
if [[ ! -f "$README_PATH" ]]; then
  echo "readme not found: $README_PATH" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

archive_base="singbox-rust-${VERSION}-${OS_NAME}-${ARCH}"
stage_root="$OUT_DIR/stage/$archive_base"
rm -rf "$stage_root"
mkdir -p "$stage_root/bin" "$stage_root/config" "$stage_root/docs"

binary_out_name="singbox-rust"
if [[ "$BINARY" == *.exe ]]; then
  binary_out_name="singbox-rust.exe"
fi

cp "$BINARY" "$stage_root/bin/$binary_out_name"
cp "$CONFIG_TEMPLATE" "$stage_root/config/config-template.json"
cp "$README_PATH" "$stage_root/docs/README.md"

archive_path="$OUT_DIR/${archive_base}.${ARCHIVE}"
rm -f "$archive_path"

if [[ "$ARCHIVE" == "tar.gz" ]]; then
  tar czf "$archive_path" -C "$OUT_DIR/stage" "$archive_base"
else
  zip_name="${archive_base}.zip"
  (
    cd "$stage_root"
    rm -f "$zip_name"
    if command -v python3 >/dev/null 2>&1; then
      python3 -m zipfile -c "$zip_name" bin config docs
    elif command -v python >/dev/null 2>&1; then
      python -m zipfile -c "$zip_name" bin config docs
    elif command -v zip >/dev/null 2>&1; then
      zip -rq "$zip_name" bin config docs
    else
      echo "no zip tool found (python/python3/zip required)" >&2
      exit 1
    fi
  )
  mv "$stage_root/$zip_name" "$archive_path"
fi

checksums_file="$OUT_DIR/checksums.txt"
if command -v sha256sum >/dev/null 2>&1; then
  checksum_line="$(sha256sum "$archive_path" | awk '{print $1 "  " $2}')"
elif command -v shasum >/dev/null 2>&1; then
  checksum_line="$(shasum -a 256 "$archive_path" | awk '{print $1 "  " $2}')"
elif command -v openssl >/dev/null 2>&1; then
  checksum_value="$(openssl dgst -sha256 "$archive_path" | awk '{print $NF}')"
  checksum_line="${checksum_value}  ${archive_path}"
else
  echo "no sha256 tool found" >&2
  exit 1
fi
printf '%s\n' "$checksum_line" >> "$checksums_file"

echo "$archive_path"
