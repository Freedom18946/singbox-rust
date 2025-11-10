#!/usr/bin/env bash
set -euo pipefail

# Verify manifest checksums for data/rules files.
#
# Usage:
#   scripts/tools/verify-data-manifest.sh --manifest ./bundle/manifest.txt [--root .]
#   scripts/tools/verify-data-manifest.sh --manifest ./bundle/manifest.json [--root .]

MANIFEST=""
ROOT="."

while [[ $# -gt 0 ]]; do
  case "$1" in
    --manifest) MANIFEST="$2"; shift 2;;
    --root) ROOT="$2"; shift 2;;
    -h|--help)
      sed -n '/^# Usage:/,/^$/p' "$0" | sed 's/^# \?//' ; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; exit 2;;
  esac
done

[[ -n "$MANIFEST" ]] || { echo "--manifest is required" >&2; exit 2; }

fail=0

sha256_one() {
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'; else sha256sum "$1" | awk '{print $1}'; fi
}

verify_txt() {
  local line sum path actual
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    sum="${line%% *}"
    path="${line#*  }"
    if [[ ! -f "$ROOT/$path" ]]; then
      echo "[x] missing: $path" >&2
      fail=1
      continue
    fi
    actual=$(sha256_one "$ROOT/$path")
    if [[ "$actual" != "$sum" ]]; then
      echo "[x] mismatch: $path expected=$sum actual=$actual" >&2
      fail=1
    else
      echo "[ok] $path"
    fi
  done < "$MANIFEST"
}

verify_json() {
  mapfile -t entries < <(jq -r '.files[] | "\(.sha256)  \(.path)"' "$MANIFEST")
  local tmp
  tmp=$(mktemp)
  printf "%s\n" "${entries[@]}" > "$tmp"
  MANIFEST="$tmp" verify_txt
  rm -f "$tmp"
}

case "$MANIFEST" in
  *.txt) verify_txt ;;
  *.json) verify_json ;;
  *) echo "Unsupported manifest type: $MANIFEST" >&2; exit 2 ;;
esac

[[ "$fail" -eq 0 ]] || exit 1
echo "[✓] All checksums verified"

