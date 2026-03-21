#!/usr/bin/env bash
set -euo pipefail
ROOT="$(CDPATH= cd -- "$(dirname -- "$0")"/../.. && pwd)"
cd "$ROOT"

changed="$(git status --porcelain || true)"

echo "[1/6] fmt/clippy/build/tests..."
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo build --bins --tests
cargo test --all --tests

echo "[2/6] explain (with trace)..."
cfg="$(mktemp)"; echo '{"inbounds":[{"type":"socks","listen":"127.0.0.1","port":1080}]}' > "$cfg"
explain_json="$( EXPLAIN_REAL=1 target/debug/app route -c "$cfg" --dest example.com:443 --explain --trace --format json )"
rm -f "$cfg"

echo "[3/6] selector simulation..."
tmpdir="$(mktemp -d)"
cleanup() {
  kill "${pid:-}" >/dev/null 2>&1 || true
  rm -rf "$tmpdir"
}
trap cleanup EXIT
cat > "$tmpdir/src_main.rs" <<'RS'
use sb_core::outbound::p3_selector::{P3Selector, PickerConfig};
fn main(){
    let mut s = P3Selector::new(vec!["a".into(),"b".into(),"c".into()], PickerConfig::default());
    for i in 0..200 {
        // a 起步好，随后 b 变强，c 不稳定
        s.record_rtt("a", 20.0 + (i as f64)*0.05);
        s.record_rtt("b", 40.0 - (i as f64)*0.1);
        s.record_rtt("c", 35.0 + ((i%5) as f64 - 2.0)*5.0);
        if i%17==0 { s.record_result("c", false); }
    }
    let p = s.pick();
    println!("{{\"pick\":\"{}\"}}", p);
}
RS
cat > "$tmpdir/Cargo.toml" <<TOML
[package]
name = "selector_sim"
version = "0.0.1"
edition = "2021"

[dependencies]
sb-core = { path = "${ROOT}/crates/sb-core" }
sb-metrics = { path = "${ROOT}/crates/sb-metrics" }
TOML
mkdir -p "$tmpdir/src"
mv "$tmpdir/src_main.rs" "$tmpdir/src/main.rs"
pushd "$tmpdir" >/dev/null
cargo run --quiet > "$tmpdir/selector_pick.json"
popd >/dev/null
selector_out="$(cat "$tmpdir/selector_pick.json")"

echo "[4/6] metrics sanity (selector metrics present optional)..."
# 若启用过 selector/pick，指标会产生；此处仅收集头部文本做日志
target/debug/run -c /dev/null --prom-listen 127.0.0.1:19090 >/dev/null 2>&1 & pid=$!
sleep 0.2
metrics_head="$(curl -sS http://127.0.0.1:19090/metrics | head -n 35 || true)"
kill "$pid" >/dev/null 2>&1 || true

echo "[5/6] pack summary..."
cat <<EOF
{
  "task":"selector_p3 + explain_real_trace",
  "git_status": $(jq -Rs . <<<"$changed"),
  "fmt_clippy_build_tests":"ok",
  "samples":{
    "explain_json": $explain_json,
    "selector_pick": $selector_out,
    "metrics_head": $(jq -Rs . <<<"$metrics_head")
  }
}
EOF

echo "[6/6] done."
