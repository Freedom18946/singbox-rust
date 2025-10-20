#!/usr/bin/env bash
set -euo pipefail

# 从 /metrics 文本抽出 metric -> [labelset JSON]
labels_extract() {
  awk '
    /^[a-zA-Z_][a-zA-Z0-9_]*({.*})?[[:space:]][0-9eE.+-]+$/ {
      metric=$1
      # 拆 label 集
      match($0, /{[^}]*}/, m)
      labels=(m[0]=="")?"":m[0]
      # 输出：metric \t {"k":"v",...}
      if (labels=="") { print metric "\t" "{}"; next }
      gsub(/^{|}$/, "", labels)
      n=split(labels, arr, /,/)
      printf "%s\t{", metric
      for (i=1;i<=n;i++) {
        split(arr[i], kv, /=/)
        k=kv[1]; v=kv[2]
        gsub(/^[[:space:]]+|[[:space:]]+$/, "", k)
        gsub(/^"|"$/, "", v)
        printf "%s\"%s\":\"%s\"", (i>1?",":""), k, v
      }
      print "}"
    }
  '
}

# 校验某 metric 的 label key/value 是否符合 allowlist 约束；行不合规则打印 JSON 诊断
labels_validate() {
  local allowlist="$1"
  local tmp_all="$(mktemp)"; echo "$allowlist" > "$tmp_all"
  local input="${2:-/dev/stdin}"
  local ok=0
  while IFS=$'\t' read -r metric json; do
    # 找到约束；若没有该 metric 的 allow，则跳过（不 gate）
    local rule="$(jq -c --arg m "$metric" '.metrics[] | select(.name==$m)' "$tmp_all" 2>/dev/null || true)"
    [[ -z "$rule" ]] && continue
    # 校验所有 keys 均在 allowlist，且值匹配正则
    for k in $(jq -r 'keys[]' <<< "$json"); do
      local re="$(jq -r --arg k "$k" '.labels[$k] // ""' <<< "$rule")"
      if [[ -z "$re" ]]; then
        echo "{\"metric\":\"$metric\",\"label\":\"$k\",\"value\":$(jq -r --arg k "$k" '.[$k]' <<< "$json"),\"error\":\"label_not_allowed\"}"
        ok=1
      else
        local val="$(jq -r --arg k "$k" '.[$k]' <<< "$json")"
        if ! [[ "$val" =~ $re ]]; then
          echo "{\"metric\":\"$metric\",\"label\":\"$k\",\"value\":\"$val\",\"error\":\"value_not_match\",\"re\":\"$re\"}"
          ok=1
        fi
      fi
    done
  done < <(cat "$input" | labels_extract)
  rm -f "$tmp_all"
  return $ok
}