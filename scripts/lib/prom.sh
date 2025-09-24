#!/usr/bin/env bash
# 极简 PromQL 子集在两次 /metrics 文本上计算
# 支持：sum(name{...}), sum by(lbl,...)(name{...}), rate(name[Ws]), increase(name[Ws]), absent(name{...})
# 新增：sum_by 返回 "key value" 多行；由上层做逐组断言（gate_group）
# 输入：两份文本文件路径 ENV: PROM_BEFORE, PROM_AFTER
set -euo pipefail

prom_find_lines() { # $1=metric name regex, $2=label_regex
  local name_re="$1"; local lr="$2"
  awk -v N="$name_re" -v L="$lr" '
    $0 ~ "^"N"\\{" && $0 ~ L { print $0 }
    $0 ~ "^"N"[[:space:]]" && L=="" { print $0 }
  ' "${PROM_AFTER}"
}

prom_label_val() { # line, key
  awk -v k="$2" '
    match($0, "\\{[^}]*\\}") {
      s=substr($0,RSTART+1,RLENGTH-2)
      n=split(s,a,",")
      for(i=1;i<=n;i++){ split(a[i],kv,"="); gsub(/"/,"",kv[2]); gsub(/^ /,"",kv[1]); if(kv[1]==k){print kv[2]; exit} }
    }' <(echo "$1")
}

prom_value_of_line() { awk '{print $NF}' <<<"$1"; }

prom_group_key() { # line, by_list(comma sep)
  local ln="$1"; local by="$2"; local key=""
  IFS=',' read -ra arr <<<"$by"
  for k in "${arr[@]}"; do
    k="${k// /}"
    [[ -z "$k" ]] && continue
    v=$(prom_label_val "$ln" "$k"); key="${key}${k}=${v},"
  done
  echo "${key%,}"
}

prom_sum() { # name_re label_re
  local total=0
  while IFS= read -r ln; do
    v=$(prom_value_of_line "$ln"); total=$(awk -v a="$total" -v b="$v" 'BEGIN{print a+b}')
  done < <(prom_find_lines "$1" "$2")
  echo "$total"
}

prom_sum_by() { # name_re label_re by_list
  # Use simulated associative array for compatibility with bash 3.x
  local tmpfile="/tmp/prom_sum_by_$$"
  : > "$tmpfile"
  local ln
  while IFS= read -r ln; do
    k=$(prom_group_key "$ln" "$3")
    v=$(prom_value_of_line "$ln")
    old=$(grep "^$k " "$tmpfile" 2>/dev/null | awk '{print $2}' || echo "0")
    new=$(awk -v a="$old" -v b="$v" 'BEGIN{print a+b}')
    grep -v "^$k " "$tmpfile" 2>/dev/null > "${tmpfile}.tmp" || true
    echo "$k $new" >> "${tmpfile}.tmp"
    mv "${tmpfile}.tmp" "$tmpfile"
  done < <(prom_find_lines "$1" "$2")
  # Output the results
  cat "$tmpfile"
  rm -f "$tmpfile" "${tmpfile}.tmp"
}

prom_rate() { # expects counter; use BEFORE/AFTER diff / seconds
  local name_re="$1"; local lr="$2"; local dur="$3"
  local sum_after=$(prom_sum "$name_re" "$lr")
  local sum_before=$(PROM_AFTER="${PROM_BEFORE}" prom_sum "$name_re" "$lr")
  awk -v a="$sum_after" -v b="$sum_before" -v d="$dur" 'BEGIN{
    if (d<=0) {print 0; exit}
    v=(a-b)/d; if (v<0) v=0; print v
  }'
}

prom_increase() { # name_re label_re dur
  local name_re="$1"; local lr="$2"; local dur="$3"
  local sum_after=$(prom_sum "$name_re" "$lr")
  local sum_before=$(PROM_AFTER="${PROM_BEFORE}" prom_sum "$name_re" "$lr")
  awk -v a="$sum_after" -v b="$sum_before" 'BEGIN{v=a-b; if (v<0) v=0; print v}'
}

prom_absent() { # name_re label_re
  local cnt=$(prom_find_lines "$1" "$2" | wc -l | tr -d ' ')
  if [[ "$cnt" -eq 0 ]]; then echo 1; else echo 0; fi
}

if [[ "$1" == "sum" ]]; then prom_sum "$2" "${3:-}"; exit 0; fi
if [[ "$1" == "sum_by" ]]; then prom_sum_by "$2" "${3:-}" "${4:-}"; exit 0; fi
if [[ "$1" == "rate" ]]; then prom_rate "$2" "${3:-}" "${4:-30}"; exit 0; fi
if [[ "$1" == "increase" ]]; then prom_increase "$2" "${3:-}" "${4:-30}"; exit 0; fi
if [[ "$1" == "absent" ]]; then prom_absent "$2" "${3:-}"; exit 0; fi
echo "usage: prom.sh sum|sum_by|rate|increase|absent <metric_re> [label_re] [seconds|by_list]" >&2
exit 2