#!/bin/bash
# Run P0 Protocol Stress Tests
#
# This script orchestrates stress testing for all P0 protocols with
# comprehensive monitoring and reporting.
#
# Usage:
#   ./scripts/run_stress_tests.sh [test_type] [duration]
#
# Test types:
#   short     - Quick stress test (5 minutes)
#   medium    - Medium stress test (1 hour)
#   long      - Long stress test (6 hours)
#   endurance - Full 24-hour endurance test
#   all       - Run all test types sequentially

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
TEST_TYPE="${1:-short}"
REPORT_DIR="reports/stress-tests"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="$REPORT_DIR/stress_test_${TEST_TYPE}_${TIMESTAMP}.log"

# Create report directory
mkdir -p "$REPORT_DIR"

# Print banner
print_banner() {
    echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║          P0 Protocol Stress Testing Suite             ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

# Print test info
print_test_info() {
    local test_type=$1
    local duration=$2
    
    echo -e "${CYAN}Test Configuration:${NC}"
    echo -e "  Type:           $test_type"
    echo -e "  Duration:       $duration"
    echo -e "  Timestamp:      $TIMESTAMP"
    echo -e "  Log File:       $LOG_FILE"
    echo ""
}

# Run baseline stress tests
run_baseline_tests() {
    local duration=$1
    
    echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}Running Baseline Stress Tests${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"
    echo ""
    
    case $duration in
        short)
            echo "Running short baseline test (60s)..."
            cargo test --test stress_tests --release -- \
                stress_baseline_short_duration --ignored --nocapture \
                2>&1 | tee -a "$LOG_FILE"
            ;;
        medium)
            echo "Running medium baseline tests..."
            cargo test --test stress_tests --release -- \
                stress_baseline_high_connection_rate --ignored --nocapture \
                2>&1 | tee -a "$LOG_FILE"
            cargo test --test stress_tests --release -- \
                stress_baseline_large_data_transfer --ignored --nocapture \
                2>&1 | tee -a "$LOG_FILE"
            ;;
        long)
            echo "Running long baseline test with monitoring..."
            cargo test --test stress_tests --release -- \
                stress_baseline_resource_monitoring --ignored --nocapture \
                2>&1 | tee -a "$LOG_FILE"
            ;;
        endurance)
            echo "Running 24-hour endurance test..."
            echo "⚠️  This will take 24 hours to complete!"
            read -p "Continue? (y/N) " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                cargo test --test stress_tests --release -- \
                    stress_baseline_24_hour_endurance --ignored --nocapture \
                    2>&1 | tee -a "$LOG_FILE"
            else
                echo "Endurance test skipped"
            fi
            ;;
    esac
}

# Run protocol-specific stress tests
run_protocol_tests() {
    local duration=$1
    
    echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}Running Protocol-Specific Stress Tests${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"
    echo ""
    
    # Check which features are enabled
    echo "Checking enabled features..."
    
    if cargo test --test stress_tests --release -- --list 2>&1 | grep -q "reality"; then
        echo -e "${GREEN}✓ REALITY TLS tests available${NC}"
    else
        echo -e "${YELLOW}⚠ REALITY TLS tests not available (feature not enabled)${NC}"
    fi
    
    if cargo test --test stress_tests --release -- --list 2>&1 | grep -q "ech"; then
        echo -e "${GREEN}✓ ECH tests available${NC}"
    else
        echo -e "${YELLOW}⚠ ECH tests not available (feature not enabled)${NC}"
    fi
    
    if cargo test --test stress_tests --release -- --list 2>&1 | grep -q "hysteria"; then
        echo -e "${GREEN}✓ Hysteria tests available${NC}"
    else
        echo -e "${YELLOW}⚠ Hysteria tests not available (feature not enabled)${NC}"
    fi
    
    if cargo test --test stress_tests --release -- --list 2>&1 | grep -q "ssh"; then
        echo -e "${GREEN}✓ SSH tests available${NC}"
    else
        echo -e "${YELLOW}⚠ SSH tests not available (feature not enabled)${NC}"
    fi
    
    if cargo test --test stress_tests --release -- --list 2>&1 | grep -q "tuic"; then
        echo -e "${GREEN}✓ TUIC tests available${NC}"
    else
        echo -e "${YELLOW}⚠ TUIC tests not available (feature not enabled)${NC}"
    fi
    
    echo ""
    echo "Note: Protocol-specific tests require running servers."
    echo "See test documentation for setup instructions."
    echo ""
}

# Run leak detection tests
run_leak_detection() {
    echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}Running Leak Detection Tests${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════${NC}"
    echo ""
    
    echo "Running memory leak detection..."
    cargo test --test stress_tests --release -- \
        stress_memory_leak_detection --ignored --nocapture \
        2>&1 | tee -a "$LOG_FILE"
    
    echo ""
    echo "Running file descriptor leak detection..."
    cargo test --test stress_tests --release -- \
        stress_file_descriptor_leak_detection --ignored --nocapture \
        2>&1 | tee -a "$LOG_FILE"
}

# Generate summary report
generate_report() {
    local report_file="$REPORT_DIR/summary_${TIMESTAMP}.txt"
    
    echo -e "${CYAN}Generating summary report...${NC}"
    
    {
        echo "P0 Protocol Stress Test Summary"
        echo "================================"
        echo ""
        echo "Test Type:    $TEST_TYPE"
        echo "Timestamp:    $TIMESTAMP"
        echo "Duration:     $(date -d @$SECONDS -u +%H:%M:%S 2>/dev/null || echo 'N/A')"
        echo ""
        echo "Test Results:"
        echo "-------------"
        
        # Extract test results from log
        if grep -q "test result:" "$LOG_FILE"; then
            grep "test result:" "$LOG_FILE" | tail -1
        else
            echo "No test results found in log"
        fi
        
        echo ""
        echo "Resource Usage:"
        echo "---------------"
        
        # Extract resource summaries
        if grep -q "Resource Monitoring Summary" "$LOG_FILE"; then
            echo "✓ Resource monitoring data available"
        else
            echo "⚠ No resource monitoring data"
        fi
        
        echo ""
        echo "Leak Detection:"
        echo "---------------"
        
        if grep -q "FD Leak Detected.*NO" "$LOG_FILE"; then
            echo "✓ No file descriptor leaks detected"
        elif grep -q "FD Leak Detected.*YES" "$LOG_FILE"; then
            echo "⚠ File descriptor leaks detected!"
        fi
        
        if grep -q "Memory Leak Detected.*NO" "$LOG_FILE"; then
            echo "✓ No memory leaks detected"
        elif grep -q "Memory Leak Detected.*YES" "$LOG_FILE"; then
            echo "⚠ Memory leaks detected!"
        fi
        
        echo ""
        echo "Full log: $LOG_FILE"
        
    } > "$report_file"
    
    cat "$report_file"
    echo ""
    echo -e "${GREEN}Summary report saved to: $report_file${NC}"
}

# Main execution
main() {
    print_banner
    
    case $TEST_TYPE in
        short)
            print_test_info "Short" "5-10 minutes"
            run_baseline_tests "short"
            run_leak_detection
            ;;
        medium)
            print_test_info "Medium" "1-2 hours"
            run_baseline_tests "medium"
            run_protocol_tests "medium"
            run_leak_detection
            ;;
        long)
            print_test_info "Long" "6 hours"
            run_baseline_tests "long"
            run_protocol_tests "long"
            run_leak_detection
            ;;
        endurance)
            print_test_info "Endurance" "24 hours"
            run_baseline_tests "endurance"
            run_protocol_tests "endurance"
            ;;
        all)
            print_test_info "All Tests" "Variable"
            run_baseline_tests "short"
            run_baseline_tests "medium"
            run_protocol_tests "medium"
            run_leak_detection
            ;;
        *)
            echo -e "${RED}Error: Unknown test type '$TEST_TYPE'${NC}"
            echo ""
            echo "Usage: $0 [test_type]"
            echo ""
            echo "Test types:"
            echo "  short     - Quick stress test (5 minutes)"
            echo "  medium    - Medium stress test (1 hour)"
            echo "  long      - Long stress test (6 hours)"
            echo "  endurance - Full 24-hour endurance test"
            echo "  all       - Run all test types sequentially"
            exit 1
            ;;
    esac
    
    echo ""
    generate_report
    
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║          Stress Testing Complete                      ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════╝${NC}"
}

# Handle Ctrl+C gracefully
trap 'echo -e "\n${YELLOW}Stress test interrupted${NC}"; exit 130' INT

# Run main
main
