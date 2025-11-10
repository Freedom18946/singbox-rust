#!/usr/bin/env bash
set -euo pipefail

# Generate manifest (sha256 and sizes) for geodata and compiled rule-sets.
#
# Usage:
#   scripts/tools/gen-data-manifest.sh --data ./data --rules ./out --out ./bundle [--format json|text|both]
#
# Outputs (into --out):
#   - manifest.txt   (lines: "<sha256>  <relative-path>")
#   - manifest.json  ({ files: [{ path, sha256, size }] })

DATA_DIR="./data"
RULES_DIR="./out"
OUT_DIR="./bundle"
FORMAT="both"  # json|text|both

while [[ $# -gt 0 ]]; do
  case "$1" in
    --data) DATA_DIR="$2"; shift 2;;
    --rules) RULES_DIR="$2"; shift 2;;
    --out) OUT_DIR="$2"; shift 2;;
    --format) FORMAT="$2"; shift 2;;
    -h|--help)
      sed -n '/^# Usage:/,/^$/p' "$0" | sed 's/^# \?//' ; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; exit 2;;
  esac
done

mkdir -p "$OUT_DIR"

sha256() {
  # prints: "<sha256>  <path>"
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1"
  else
    sha256sum "$1"
  fi
}

add_file() {
  local p="$1"
  local rel="$2"  # relative path shown in manifest
  [[ -f "$p" ]] || return 0
  local sum size
  sum=$(sha256 "$p" | awk '{print $1}')
  # macOS vs GNU stat
  if size=$(stat -f%z "$p" 2>/dev/null); then :; else size=$(stat -c%s "$p"); fi
  FILES_JSON+="$(printf '{"path":"%s","sha256":"%s","size":%s},' "$rel" "$sum" "$size")"
  FILES_TXT+="$(printf '%s  %s\n' "$sum" "$rel")"
}

FILES_JSON=""
FILES_TXT=""

# Geo databases
add_file "$DATA_DIR/geoip.db" "data/geoip.db"
add_file "$DATA_DIR/geosite.db" "data/geosite.db"

# Rule-sets
shopt -s nullglob
for f in "$RULES_DIR"/*.srs; do
  base=$(basename "$f")
  add_file "$f" "rules/$base"
done
shopt -u nullglob

# Write manifests
if [[ -z "$FILES_JSON" && -z "$FILES_TXT" ]]; then
  echo "[warn] No inputs found under $DATA_DIR or $RULES_DIR" >&2
fi

if [[ "$FORMAT" == "json" || "$FORMAT" == "both" ]]; then
  # trim trailing comma
  FILES_JSON="[${FILES_JSON%,}]"
  jq -n --arg ts "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg data "$DATA_DIR" --arg rules "$RULES_DIR" \
     --arg tool "gen-data-manifest.sh" '{
       generated_at: $ts,
       tool: $tool,
       inputs: { data_dir: $data, rules_dir: $rules },
       files: $FILES
     }' --argjson FILES "$FILES_JSON" > "$OUT_DIR/manifest.json"
  echo "[✓] Wrote $OUT_DIR/manifest.json"
fi

if [[ "$FORMAT" == "text" || "$FORMAT" == "both" ]]; then
  printf "%s" "$FILES_TXT" > "$OUT_DIR/manifest.txt"
  echo "[✓] Wrote $OUT_DIR/manifest.txt"
fi

