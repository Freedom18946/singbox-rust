#!/usr/bin/env bash
set -euo pipefail
DIR="${1:-.}"

xml_escape_attr() {
  # escape only the critical characters for XML attributes
  sed -e 's/&/&amp;/g' -e 's/"/&quot;/g' -e "s/'/&apos;/g" -e 's/</&lt;/g' -e 's/>/&gt;/g'
}

echo '<?xml version="1.0" encoding="UTF-8"?>'
echo '<testsuite name="singbox-rust-e2e">'
for f in "${DIR}"/*.json; do
  name="$(basename "$f")"
  total=$(jq -r '.report.total // 0' "$f" 2>/dev/null || echo 0)
  failed=$(jq -r '.report.failed // 0' "$f" 2>/dev/null || echo 0)
  echo "  <testsuite name=\"$name\" tests=\"$total\" failures=\"$failed\">"

  jq -c '.scenarios[]? | {name:.name, ok:(.ok==true or .ok==1), msg:(.msg//""), asserts:(.asserts//[])}' "$f" 2>/dev/null \
  | while read -r line; do
      n=$(jq -r '.name' <<<"$line")
      ok=$(jq -r '.ok' <<<"$line")
      msg=$(jq -r '.msg' <<<"$line" | xml_escape_attr)
      if [[ "$ok" == "true" ]]; then
        echo "    <testcase name=\"$n\"/>"
      else
        diag=$(jq -r '.asserts[]? | select(.ok==0) | (.name // .value // .compare) + ":" + (.label // (.left+"|"+.right) // (.by // "")) + " cur=" + ((.cur // .delta // .diff // 0|tostring)) + " expect=" + ((.expect // .min // .gap // 0|tostring))' <<<"$line" | paste -sd'; ' - | xml_escape_attr)
        echo "    <testcase name=\"$n\"><failure message=\"$msg\">$diag</failure></testcase>"

        # Expand grouped PromQL failures into separate testcases when gate_group=1
        # Detect prom asserts with .by and .groups and .ok==0
        jq -r --arg n "$n" '
          .asserts[]? 
          | select((.name|tostring|startswith("prom:")) and (.by? != null) and (.ok==0))
          | . as $a
          | ($a.name|tostring|sub("^prom:";"")) as $expr
          | ($a.op // "") as $op
          | ($a.expect // 0) as $expect
          | ($a.owner // "") as $owner
          | ($a.severity // "") as $severity
          | ($a.fail // "") as $fails
          | ($a.groups // "") as $groups
          | ($groups | split("\n") | map(select(length>0)) ) as $rows
          | ($fails | split(",") | map(select(length>0)) ) as $bad
          | $bad[]
          | . as $key
          | ($rows[] | select(startswith($key + " ")) ) as $kv
          | ($kv | capture("^(?<k>.*) (?<v>.*)$") ) as $pair
          | "    <testcase name=\"\($n)/PROM group=\($pair.k)\"><failure message=\"expr=\($expr), cur=\($pair.v), \($op) \($expect) [\($owner)][\($severity)]\"></failure></testcase>"
        ' <<<"$line" | xml_escape_attr | sed 's/&quot;/"/g'
      fi
    done
  echo "  </testsuite>"
done
echo '</testsuite>'
