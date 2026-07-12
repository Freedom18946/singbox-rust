#!/bin/sh
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/../../.." && pwd)
target_dir=${INTEROP_ACCEPTANCE_APP_TARGET_DIR:-${INTEROP_PROTOCOL_APP_TARGET_DIR:-"$repo_root/target/interop-protocol-app"}}
binary="$target_dir/debug/app"

CARGO_TARGET_DIR="$target_dir" cargo build \
  --manifest-path "$repo_root/Cargo.toml" \
  -p app \
  --features acceptance,clash_api,adapters \
  --bin app >&2

exec "$binary" "$@"
