#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "== Feature audit =="
echo "workspace: $root"

RED="$(printf '\033[31m')"; GRN="$(printf '\033[32m')"; YLW="$(printf '\033[33m')"; NC="$(printf '\033[0m')"

fail=0

# 1) 收集每个 crate 的 features 定义
declare -A defmap
while IFS= read -r cargo; do
  crate_dir="$(dirname "$cargo")"
  crate_name="$(grep -m1 '^name\s*=' "$cargo" | sed -E 's/.*"([^"]+)".*/\1/')"
  feats="$(awk '
    BEGIN{infeat=0}
    /^\[features\]/{infeat=1; next}
    /^\[/{if(infeat){exit} else {next}}
    infeat && $0 !~ /^[[:space:]]*(#|;|\/\/)/ && $0 ~ /=/ {
      gsub(/[[:space:]]/,"",$0);
      split($0, a, "=");
      print a[1];
    }
  ' "$cargo" | sort -u | tr '\n' ' ')"
  defmap["$crate_dir"]="$feats"
done < <(find "$root" -name Cargo.toml -not -path "*/target/*")

# 2) 扫描代码里用到的 cfg(feature="X")
declare -A usemap
while IFS= read -r rs; do
  crate_dir="$(dirname "$(dirname "$rs")")"
  used="$(grep -hoRE '#\[cfg[[:space:]]*\((any|all)\([^)]*feature *= *"[^"]+"' -e '#\[cfg[[:space:]]*\(feature *= *"[^"]+"' "$crate_dir/src" 2>/dev/null \
          | sed -E 's/.*feature *= *"([^"]+)".*/\1/' | sort -u | tr '\n' ' ' || true)"
  usemap["$crate_dir"]="$used"
done < <(find "$root" -path "*/src/*.rs" -not -path "*/target/*")

# 3) 比对并报告
echo
for dir in "${!usemap[@]}"; do
  used="${usemap[$dir]}"
  defd="${defmap[$dir]}"
  IFS=' ' read -r -a uarr <<< "$used"
  IFS=' ' read -r -a darr <<< "$defd"
  # to sets
  declare -A u; for x in "${uarr[@]}"; do [[ -n "$x" ]] && u["$x"]=1; done
  declare -A d; for x in "${darr[@]}"; do [[ -n "$x" ]] && d["$x"]=1; done
  # used but not defined
  ubnd=()
  for x in "${!u[@]}"; do [[ -z "${d[$x]:-}" ]] && ubnd+=("$x"); done
  # defined but not used
  dbnu=()
  for x in "${!d[@]}"; do [[ -z "${u[$x]:-}" ]] && dbnu+=("$x"); done

  crate_name="$(grep -m1 '^name\s*=' "$dir/Cargo.toml" | sed -E 's/.*"([^"]+)".*/\1/')"
  if ((${#ubnd[@]})); then
    echo -e "${RED}[used-not-defined]${NC} $crate_name -> ${ubnd[*]}"
    fail=1
  fi
  if ((${#dbnu[@]})); then
    echo -e "${YLW}[defined-not-used]${NC} $crate_name -> ${dbnu[*]}"
  fi
done

echo
if ((fail)); then
  echo -e "${RED}Feature audit failed.${NC}"
  exit 1
else
  echo -e "${GRN}Feature audit passed.${NC}"
fi