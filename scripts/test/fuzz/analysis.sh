#!/bin/bash
# Fuzz testing analysis and quick run script
# Usage:
#   ./scripts/fuzz-analysis.sh status   - Show current fuzz coverage
#   ./scripts/fuzz-analysis.sh quick    - Run quick fuzz test (30s each)
#   ./scripts/fuzz-analysis.sh run TARGET - Run specific fuzz target

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Project root
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

# Function to check if a protocol has fuzz coverage
check_protocol_coverage() {
    local protocol=$1
    local fuzz_target=$2
    
    if [ -f "fuzz/fuzz_targets/$fuzz_target" ]; then
        echo -e "${GREEN}✓${NC} $protocol - $fuzz_target"
        return 0
    else
        echo -e "${RED}✗${NC} $protocol - $fuzz_target ${YELLOW}(MISSING)${NC}"
        return 1
    fi
}

# Show current status
show_status() {
    echo -e "${BLUE}=== Fuzz Coverage Status ===${NC}\n"
    
    echo -e "${BLUE}Existing targets:${NC}"
    local count=0
    for target in fuzz/fuzz_targets/*.rs; do
        if [ -f "$target" ]; then
            name=$(basename "$target" .rs)
            size=$(wc -l < "$target")
            
            # Check if it's a real implementation or stub
            if [ "$size" -lt 10 ]; then
                echo -e "  ${YELLOW}⚠${NC}  $name ${YELLOW}(stub, $size lines)${NC}"
            else
                echo -e "  ${GREEN}✓${NC}  $name ($size lines)"
                ((count++))
            fi
        fi
    done
    echo -e "\nTotal valid targets: ${GREEN}$count${NC}\n"
    
    echo -e "${BLUE}Protocol coverage analysis:${NC}"
    local missing=0
    
    # Core protocols
    check_protocol_coverage "SOCKS5 UDP" "fuzz_socks_udp.rs" || ((missing++))
    check_protocol_coverage "DNS Message" "fuzz_dns_message.rs" || ((missing++))
    check_protocol_coverage "Config Parser" "fuzz_config.rs" || ((missing++))
    
    # Critical missing protocols
    check_protocol_coverage "VMess" "fuzz_vmess.rs" || ((missing++))
    check_protocol_coverage "VLESS" "fuzz_vless.rs" || ((missing++))
    check_protocol_coverage "VLESS (new)" "fuzz_vless_parsing.rs" || true  # new file
    check_protocol_coverage "Trojan" "fuzz_trojan.rs" || ((missing++))
    check_protocol_coverage "Shadowsocks" "fuzz_shadowsocks.rs" || ((missing++))
    check_protocol_coverage "Hysteria v1" "fuzz_hysteria.rs" || ((missing++))
    check_protocol_coverage "Hysteria v2" "fuzz_hysteria2.rs" || ((missing++))
    check_protocol_coverage "TUIC" "fuzz_tuic.rs" || ((missing++))
    check_protocol_coverage "TUN Packets" "fuzz_tun_packet.rs" || ((missing++))
    check_protocol_coverage "Mixed Protocol" "fuzz_mixed_protocol.rs" || ((missing++))
    check_protocol_coverage "HTTP CONNECT" "fuzz_http_connect.rs" || ((missing++))
    
    echo -e "\n${RED}Missing coverage: $missing protocols${NC}"
    
    # Check sb-adapters fuzz
    echo -e "\n${BLUE}sb-adapters fuzz status:${NC}"
    if [ -d "crates/sb-adapters/fuzz" ]; then
        echo -e "  ${YELLOW}⚠${NC}  Duplicate fuzz workspace exists at crates/sb-adapters/fuzz/"
        echo -e "  ${YELLOW}→${NC}  Recommendation: Consolidate into root /fuzz/ directory"
        
        for target in crates/sb-adapters/fuzz/fuzz_targets/*.rs; do
            if [ -f "$target" ]; then
                name=$(basename "$target" .rs)
                size=$(wc -l < "$target")
                
                if [ "$size" -lt 10 ]; then
                    echo -e "    ${RED}✗${NC} $name ${RED}(stub/empty)${NC}"
                elif grep -q "^fn " "$target" | head -5; then
                    echo -e "    ${YELLOW}⚠${NC} $name ${YELLOW}(uses mock functions, not real code)${NC}"
                else
                    echo -e "    ${GREEN}✓${NC} $name"
                fi
            fi
        done
    else
        echo -e "  ${GREEN}✓${NC} No duplicate fuzz workspace"
    fi
    
    # Corpus status
    echo -e "\n${BLUE}Corpus status:${NC}"
    if [ -d "fuzz/corpus" ]; then
        for corpus_dir in fuzz/corpus/*/; do
            if [ -d "$corpus_dir" ]; then
                name=$(basename "$corpus_dir")
                count=$(find "$corpus_dir" -type f | wc -l)
                
                if [ "$count" -eq 0 ]; then
                    echo -e "  ${YELLOW}⚠${NC}  $name: ${YELLOW}empty${NC}"
                elif [ "$count" -lt 3 ]; then
                    echo -e "  ${YELLOW}⚠${NC}  $name: $count seeds ${YELLOW}(recommend 5+)${NC}"
                else
                    echo -e "  ${GREEN}✓${NC}  $name: $count seeds"
                fi
            fi
        done
    fi
    
    # Recommendations
    echo -e "\n${BLUE}=== Priority Recommendations ===${NC}"
    echo -e "${RED}P0 (Critical):${NC}"
    echo "  1. Delete or implement fuzz_target_1.rs (empty stub)"
    echo "  2. Add fuzz_vmess.rs (VMess auth parsing)"
    echo "  3. Add fuzz_trojan.rs (Trojan password hash)"
    echo -e "${YELLOW}P1 (High):${NC}"
    echo "  4. Add fuzz_shadowsocks.rs (AEAD parsing)"
    echo "  5. Add fuzz_tun_packet.rs (IPv4/IPv6 parsing)"
    echo "  6. Refactor sb-adapters fuzz to use real code"
    echo -e "${GREEN}P2 (Improvement):${NC}"
    echo "  7. Add structured fuzzing with 'arbitrary' crate"
    echo "  8. Set up CI for continuous fuzzing"
    echo "  9. Generate comprehensive corpus for all protocols"
    
    echo -e "\n${BLUE}See fuzz/README.md for full details and usage guide${NC}"
}

# Quick fuzz test (30 seconds each)
quick_fuzz() {
    echo -e "${BLUE}=== Quick Fuzz Test (30s per target) ===${NC}\n"
    
    # Check if cargo-fuzz is installed
    if ! command -v cargo-fuzz &> /dev/null; then
        echo -e "${RED}Error: cargo-fuzz not found${NC}"
        echo "Install with: cargo install cargo-fuzz"
        exit 1
    fi
    
    # Check if nightly toolchain is available
    if ! rustup toolchain list | grep -q nightly; then
        echo -e "${YELLOW}Warning: nightly toolchain not found${NC}"
        echo "Install with: rustup toolchain install nightly"
        exit 1
    fi
    
    local targets=(
        "fuzz_config"
        "fuzz_dns_message"
        "fuzz_socks_udp"
        "fuzz_vless_parsing"
    )
    
    for target in "${targets[@]}"; do
        if [ -f "fuzz/fuzz_targets/$target.rs" ]; then
            echo -e "${GREEN}Running $target...${NC}"
            
            # Run with timeout and capture stats
            timeout 30s cargo +nightly fuzz run "$target" -- \
                -max_total_time=30 \
                -print_final_stats=1 \
                2>&1 | tail -5 || true
            
            echo ""
        else
            echo -e "${YELLOW}Skipping $target (not found)${NC}"
        fi
    done
    
    echo -e "${GREEN}Quick fuzz test complete!${NC}"
    echo "Check fuzz/artifacts/ for any crashes"
}

# Run specific target
run_target() {
    local target=$1
    
    if [ -z "$target" ]; then
        echo -e "${RED}Error: No target specified${NC}"
        echo "Usage: $0 run <target_name>"
        exit 1
    fi
    
    if [ ! -f "fuzz/fuzz_targets/$target.rs" ]; then
        echo -e "${RED}Error: Target $target not found${NC}"
        exit 1
    fi
    
    echo -e "${BLUE}Running $target (Ctrl+C to stop)${NC}\n"
    
    cargo +nightly fuzz run "$target"
}

# List all available targets
list_targets() {
    echo -e "${BLUE}Available fuzz targets:${NC}\n"
    
    for target in fuzz/fuzz_targets/*.rs; do
        if [ -f "$target" ]; then
            name=$(basename "$target" .rs)
            echo "  - $name"
        fi
    done
}

# Main command dispatcher
case "${1:-status}" in
    status|check)
        show_status
        ;;
    quick)
        quick_fuzz
        ;;
    run)
        run_target "$2"
        ;;
    list)
        list_targets
        ;;
    help|--help|-h)
        echo "Usage: $0 <command> [options]"
        echo ""
        echo "Commands:"
        echo "  status    - Show current fuzz coverage status (default)"
        echo "  quick     - Run quick fuzz test (30s each target)"
        echo "  run <target> - Run specific fuzz target"
        echo "  list      - List all available targets"
        echo "  help      - Show this help message"
        ;;
    *)
        echo -e "${RED}Unknown command: $1${NC}"
        echo "Run '$0 help' for usage"
        exit 1
        ;;
esac

