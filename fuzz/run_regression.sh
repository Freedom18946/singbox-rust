#!/usr/bin/env bash
# Fuzz regression test runner for singbox-rust
# Usage:
#   ./run_regression.sh                  # Run all regression + seed smoke tests
#   ./run_regression.sh --seeds-only     # Only run seed corpus smoke tests
#   ./run_regression.sh --target <name>  # Run single target
set -euo pipefail

FUZZ_DIR="$(cd "$(dirname "$0")" && pwd)"
SEEDS_DIR="$FUZZ_DIR/corpus/seeds"
REGRESSION_DIR="$FUZZ_DIR/regression"

SEEDS_ONLY=false
SINGLE_TARGET=""
PASSED=0
FAILED=0
SKIPPED=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --seeds-only) SEEDS_ONLY=true; shift ;;
        --target) SINGLE_TARGET="$2"; shift 2 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# Target → seed dir mapping (skip arbitrary-based targets for seed runs)
declare -A TARGET_SEEDS=(
    [fuzz_config]=config
    [fuzz_dns_message]=dns_message
    [fuzz_route_decide]=route_decide
    [fuzz_sniff_tls]=sniff_tls
    [fuzz_sniff_http]=sniff_http
    [fuzz_sniff_quic]=sniff_quic
    [fuzz_sniff_stream]=sniff_stream
    [fuzz_vmess]=vmess
    [fuzz_vless]=vless
    [fuzz_shadowsocks]=shadowsocks
    [fuzz_trojan]=trojan
    [fuzz_hysteria]=hysteria
    [fuzz_tuic]=tuic
    [fuzz_socks5]=socks5
    [fuzz_http_connect]=http_connect
    [fuzz_tun_packet]=tun
    [fuzz_mixed_protocol]=mixed
    [fuzz_v2ray_api]=v2ray_api
)

# Target → regression dir mapping
declare -A TARGET_REGRESSION=(
    [fuzz_config]=core
    [fuzz_config_structured]=core
    [fuzz_dns_message]=core
    [fuzz_route_decide]=core
    [fuzz_sniff_tls]=core
    [fuzz_sniff_http]=core
    [fuzz_sniff_quic]=core
    [fuzz_sniff_stream]=core
    [fuzz_vmess]=protocols
    [fuzz_vless]=protocols
    [fuzz_shadowsocks]=protocols
    [fuzz_trojan]=protocols
    [fuzz_hysteria]=protocols
    [fuzz_tuic]=protocols
    [fuzz_socks5]=protocols
    [fuzz_http_connect]=protocols
    [fuzz_vmess_structured]=protocols
    [fuzz_tun_packet]=network
    [fuzz_mixed_protocol]=network
    [fuzz_v2ray_api]=api
)

run_target_seeds() {
    local target="$1"
    local seed_dir="${TARGET_SEEDS[$target]:-}"

    if [[ -z "$seed_dir" ]]; then
        echo "  SKIP $target (arbitrary-based, no seed corpus)"
        ((SKIPPED++)) || true
        return 0
    fi

    local full_seed_path="$SEEDS_DIR/$seed_dir"
    if [[ ! -d "$full_seed_path" ]] || [[ -z "$(ls -A "$full_seed_path" 2>/dev/null)" ]]; then
        echo "  SKIP $target (no seeds in $seed_dir/)"
        ((SKIPPED++)) || true
        return 0
    fi

    local seed_count
    seed_count=$(find "$full_seed_path" -type f | wc -l | tr -d ' ')

    echo -n "  SEED $target ($seed_count files)... "

    # Run all seed files through the fuzz target at once (corpus dir mode, -runs=0 = process existing only)
    local output
    if output=$(cargo +nightly fuzz run "$target" "$full_seed_path" -- -runs=0 2>&1); then
        echo "PASS"
        ((PASSED++)) || true
    else
        echo "FAIL"
        echo "$output" | tail -5 | sed 's/^/    /'
        ((FAILED++)) || true
        return 1
    fi
}

run_target_regression() {
    local target="$1"
    local reg_subdir="${TARGET_REGRESSION[$target]:-}"

    if [[ -z "$reg_subdir" ]]; then
        return 0
    fi

    local reg_path="$REGRESSION_DIR/$reg_subdir"

    # Check if any regression files exist for this target (named <target>-*)
    local reg_count
    reg_count=$(find "$reg_path" -name "${target}-*" -type f 2>/dev/null | wc -l | tr -d ' ')

    if [[ "$reg_count" -eq 0 ]]; then
        return 0  # No regression inputs, nothing to do
    fi

    # Create a temp dir with only this target's regression files
    local tmp_reg
    tmp_reg=$(mktemp -d)
    find "$reg_path" -name "${target}-*" -type f -exec cp {} "$tmp_reg/" \;

    echo -n "  REG  $target ($reg_count files)... "

    local output
    if output=$(cargo +nightly fuzz run "$target" "$tmp_reg" -- -runs=0 2>&1); then
        echo "PASS"
        ((PASSED++)) || true
    else
        echo "FAIL (REGRESSION!)"
        echo "$output" | tail -5 | sed 's/^/    /'
        ((FAILED++)) || true
        rm -rf "$tmp_reg"
        return 1
    fi
    rm -rf "$tmp_reg"
}

echo "=== singbox-rust fuzz regression runner ==="
echo ""

# Build all fuzz targets first
echo "Building fuzz targets..."
if ! cargo +nightly fuzz build 2>&1 | tail -1; then
    echo "ERROR: cargo fuzz build failed"
    exit 1
fi
echo ""

# Determine which targets to run
if [[ -n "$SINGLE_TARGET" ]]; then
    TARGETS=("$SINGLE_TARGET")
else
    TARGETS=(
        fuzz_config fuzz_dns_message fuzz_route_decide
        fuzz_sniff_tls fuzz_sniff_http fuzz_sniff_quic fuzz_sniff_stream
        fuzz_vmess fuzz_vless fuzz_shadowsocks fuzz_trojan
        fuzz_hysteria fuzz_tuic fuzz_socks5 fuzz_http_connect
        fuzz_tun_packet fuzz_mixed_protocol fuzz_v2ray_api
        fuzz_config_structured fuzz_vmess_structured
    )
fi

# Run seed smoke tests
echo "--- Seed corpus smoke tests ---"
for target in "${TARGETS[@]}"; do
    run_target_seeds "$target" || true
done
echo ""

# Run regression tests (unless --seeds-only)
if [[ "$SEEDS_ONLY" == false ]]; then
    echo "--- Regression tests ---"
    has_regression=false
    for target in "${TARGETS[@]}"; do
        local_reg_subdir="${TARGET_REGRESSION[$target]:-}"
        if [[ -n "$local_reg_subdir" ]]; then
            local_reg_path="$REGRESSION_DIR/$local_reg_subdir"
            if [[ -d "$local_reg_path" ]] && find "$local_reg_path" -name "${target}-*" -type f -print0 2>/dev/null | grep -qz .; then
                has_regression=true
            fi
        fi
        run_target_regression "$target" || true
    done

    if [[ "$has_regression" == false ]]; then
        echo "  (no regression inputs found -- add crash files as <target>-<desc> in regression/<category>/)"
    fi
    echo ""
fi

# Summary
echo "=== Summary ==="
echo "  Passed:  $PASSED"
echo "  Failed:  $FAILED"
echo "  Skipped: $SKIPPED"
echo ""

if [[ $FAILED -gt 0 ]]; then
    echo "RESULT: FAIL"
    exit 1
else
    echo "RESULT: PASS"
    exit 0
fi
