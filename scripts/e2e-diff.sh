#!/bin/bash
set -euo pipefail

# E2E compatibility difference reporter
# Compares Rust vs Go sing-box outputs and generates diff summaries

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DIFF_DIR="$ROOT_DIR/target/e2e-diff"

# Ensure diff output directory exists
mkdir -p "$DIFF_DIR"

# Check if GO_SINGBOX_BIN is available
if [ -z "${GO_SINGBOX_BIN:-}" ]; then
    echo "[e2e-diff] GO_SINGBOX_BIN not set; diff reporting disabled"
    exit 1
fi

if [ ! -x "$GO_SINGBOX_BIN" ]; then
    echo "[e2e-diff] GO_SINGBOX_BIN ($GO_SINGBOX_BIN) not executable"
    exit 1
fi

# Build Rust binary
echo "[e2e-diff] Building Rust sing-box..."
cd "$ROOT_DIR"
cargo build --release --bin singbox-rust

RUST_BIN="$ROOT_DIR/target/release/singbox-rust"
if [ ! -x "$RUST_BIN" ]; then
    echo "[e2e-diff] Failed to build Rust binary"
    exit 1
fi

# Test configurations and destinations
declare -a TEST_CASES=(
    "minimal.yaml:example.com:443:tcp"
    "minimal.yaml:udp.example.com:53:udp"
    "minimal.yaml:api.github.com:443:tcp"
    "minimal.yaml:8.8.8.8:53:tcp"
    "minimal.yaml:1.1.1.1:443:tcp"
    "minimal.yaml:proxy.example.com:443:tcp"
    "minimal.yaml:secure-dns.example.com:853:tcp"
    "minimal.yaml:doh.example.com:443:tcp"
)

run_comparison() {
    local config="$1"
    local dest="$2"
    local proto="$3"
    local test_name="$4"

    echo "[e2e-diff] Comparing $test_name..."

    # Run Go version
    local go_args=("route" "--config" "$config" "--dest" "$dest" "--explain" "--format" "json")
    if [ "$proto" != "tcp" ]; then
        go_args+=("--protocol" "$proto")
    fi

    local go_output
    if go_output=$("$GO_SINGBOX_BIN" "${go_args[@]}" 2>/dev/null); then
        echo "$go_output" > "$DIFF_DIR/${test_name}_go.json"
    else
        echo "null" > "$DIFF_DIR/${test_name}_go.json"
        echo "[e2e-diff] Go binary failed for $test_name"
    fi

    # Run Rust version
    local rust_output
    if rust_output=$("$RUST_BIN" "${go_args[@]}" 2>/dev/null); then
        echo "$rust_output" > "$DIFF_DIR/${test_name}_rust.json"
    else
        echo "null" > "$DIFF_DIR/${test_name}_rust.json"
        echo "[e2e-diff] Rust binary failed for $test_name"
    fi

    # Generate diff summary
    local summary_file="$DIFF_DIR/${test_name}_diff.json"
    cat > "$summary_file" << EOF
{
  "test_name": "$test_name",
  "config": "$config",
  "dest": "$dest",
  "protocol": "$proto",
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "go_success": $([ -s "$DIFF_DIR/${test_name}_go.json" ] && [ "$(cat "$DIFF_DIR/${test_name}_go.json")" != "null" ] && echo "true" || echo "false"),
  "rust_success": $([ -s "$DIFF_DIR/${test_name}_rust.json" ] && [ "$(cat "$DIFF_DIR/${test_name}_rust.json")" != "null" ] && echo "true" || echo "false"),
  "outputs_identical": $(if [ -f "$DIFF_DIR/${test_name}_go.json" ] && [ -f "$DIFF_DIR/${test_name}_rust.json" ]; then
    if cmp -s "$DIFF_DIR/${test_name}_go.json" "$DIFF_DIR/${test_name}_rust.json"; then
      echo "true"
    else
      echo "false"
    fi
  else
    echo "false"
  fi)
}
EOF
}

# Run comparisons
total_tests=0
successful_comparisons=0
identical_outputs=0

for test_case in "${TEST_CASES[@]}"; do
    IFS=':' read -r config dest port proto <<< "$test_case"
    test_name="${config%.*}_${dest//[^a-zA-Z0-9]/_}_${port}_${proto}"

    run_comparison "$config" "${dest}:${port}" "$proto" "$test_name"

    total_tests=$((total_tests + 1))

    # Check if comparison was successful
    if [ -f "$DIFF_DIR/${test_name}_diff.json" ]; then
        successful_comparisons=$((successful_comparisons + 1))

        # Check if outputs are identical
        if jq -r '.outputs_identical' "$DIFF_DIR/${test_name}_diff.json" | grep -q "true"; then
            identical_outputs=$((identical_outputs + 1))
        fi
    fi
done

# Generate overall summary
cat > "$DIFF_DIR/summary.json" << EOF
{
  "timestamp": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "total_tests": $total_tests,
  "successful_comparisons": $successful_comparisons,
  "identical_outputs": $identical_outputs,
  "compatibility_percentage": $(echo "scale=2; $identical_outputs * 100 / $total_tests" | bc -l),
  "diff_files_location": "$DIFF_DIR"
}
EOF

echo "[e2e-diff] Summary generated:"
echo "  Total tests: $total_tests"
echo "  Successful comparisons: $successful_comparisons"
echo "  Identical outputs: $identical_outputs"
echo "  Compatibility: $(echo "scale=1; $identical_outputs * 100 / $total_tests" | bc -l)%"
echo "  Results stored in: $DIFF_DIR"

# Exit with non-zero if not all outputs are identical (for human review)
if [ $identical_outputs -ne $total_tests ]; then
    echo "[e2e-diff] Not all outputs identical - manual review recommended"
    exit 1
fi

echo "[e2e-diff] All outputs identical - perfect compatibility!"
exit 0