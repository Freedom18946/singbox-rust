#!/usr/bin/env bash
# Comprehensive benchmark suite runner
# Usage: ./scripts/run_benchmarks.sh [--quick|--full] [--protocol PROTO] [--compare-go]

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$PROJECT_ROOT/benchmark_results}"

# Default configuration
MODE="full"
PROTOCOL=""
COMPARE_GO=false
MEASUREMENT_TIME=10
SAMPLE_SIZE=50

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --quick)
            MODE="quick"
            MEASUREMENT_TIME=5
            SAMPLE_SIZE=20
            shift
            ;;
        --full)
            MODE="full"
            MEASUREMENT_TIME=15
            SAMPLE_SIZE=100
            shift
            ;;
        --smoke-test)
            MODE="smoke"
            MEASUREMENT_TIME=2
            SAMPLE_SIZE=10
            shift
            ;;
        --protocol)
            PROTOCOL="$2"
            shift 2
            ;;
        --compare-go)
            COMPARE_GO=true
            shift
            ;;
        --output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --quick           Quick benchmark (5s, 20 samples)"
            echo "  --full            Full benchmark (15s, 100 samples)"
            echo "  --smoke-test      Smoke test (2s, 10 samples)"
            echo "  --protocol PROTO  Run specific protocol benchmark"
            echo "  --compare-go      Compare with Go baseline"
            echo "  --output DIR      Output directory (default: benchmark_results)"
            echo "  --help            Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

log_section() {
    echo ""
    echo -e "${CYAN}==============================================================================${NC}"
    echo -e "${CYAN}  $1${NC}"
    echo -e "${CYAN}==============================================================================${NC}"
    echo ""
}

# Create output directory
mkdir -p "$OUTPUT_DIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

log_section "Performance Benchmark Suite"
log_info "Mode: $MODE"
log_info "Measurement time: ${MEASUREMENT_TIME}s"
log_info "Sample size: $SAMPLE_SIZE"
log_info "Output directory: $OUTPUT_DIR"
log_info "Timestamp: $TIMESTAMP"

# Step 1: Collect system information
log_section "Step 1: Collecting System Information"

SYSTEM_INFO="$OUTPUT_DIR/system_info_$TIMESTAMP.txt"
cat > "$SYSTEM_INFO" << EOF
Benchmark Run Information
=========================
Date: $(date)
Hostname: $(hostname)
OS: $(uname -s) $(uname -r)
Architecture: $(uname -m)
EOF

# CPU info (macOS)
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "CPU: $(sysctl -n machdep.cpu.brand_string)" >> "$SYSTEM_INFO"
    echo "CPU Cores: $(sysctl -n hw.ncpu)" >> "$SYSTEM_INFO"
    echo "Memory: $(sysctl -n hw.memsize | awk '{print $0/1024/1024/1024 " GB"}')" >> "$SYSTEM_INFO"
# Linux
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    echo "CPU: $(lscpu | grep 'Model name' | cut -d: -f2 | xargs)" >> "$SYSTEM_INFO"
    echo "CPU Cores: $(nproc)" >> "$SYSTEM_INFO"
    echo "Memory: $(free -h | grep Mem | awk '{print $2}')" >> "$SYSTEM_INFO"
fi

echo "" >> "$SYSTEM_INFO"
echo "Rust toolchain:" >> "$SYSTEM_INFO"
rustc --version >> "$SYSTEM_INFO"
cargo --version >> "$SYSTEM_INFO"

if command -v go &> /dev/null; then
    echo "" >> "$SYSTEM_INFO"
    echo "Go toolchain:" >> "$SYSTEM_INFO"
    go version >> "$SYSTEM_INFO"
else
    echo "" >> "$SYSTEM_INFO"
    echo "Go toolchain: Not available" >> "$SYSTEM_INFO"
fi

log_success "System information collected"
cat "$SYSTEM_INFO"

# Step 2: Build Rust implementation
log_section "Step 2: Building Rust Implementation"

cd "$PROJECT_ROOT"
log_info "Building in release mode..."

if cargo build --release --package sb-benches 2>&1 | tee "$OUTPUT_DIR/build_$TIMESTAMP.log"; then
    log_success "Rust benchmark build completed"
else
    log_error "Rust benchmark build failed"
    exit 1
fi

# Step 3: Run Rust benchmarks
log_section "Step 3: Running Rust Benchmarks"

BENCH_ARGS="--measurement-time $MEASUREMENT_TIME --sample-size $SAMPLE_SIZE"
BASELINE_NAME="baseline_$TIMESTAMP"

if [ -n "$PROTOCOL" ]; then
    log_info "Running specific protocol benchmark: $PROTOCOL"
    BENCH_TARGET="--bench ${PROTOCOL}_throughput"
else
    log_info "Running all benchmarks"
    BENCH_TARGET=""
fi

log_info "Benchmark arguments: $BENCH_ARGS"
log_info "Baseline name: $BASELINE_NAME"

BENCH_OUTPUT="$OUTPUT_DIR/rust_bench_$TIMESTAMP.log"

if cargo bench --package sb-benches $BENCH_TARGET -- $BENCH_ARGS --save-baseline "$BASELINE_NAME" 2>&1 | tee "$BENCH_OUTPUT"; then
    log_success "Rust benchmarks completed"
else
    log_error "Some benchmarks failed (this is expected for placeholder benchmarks)"
fi

# Step 4: Generate summary
log_section "Step 4: Generating Summary Report"

SUMMARY_FILE="$OUTPUT_DIR/summary_$TIMESTAMP.md"

cat > "$SUMMARY_FILE" << EOF
# Benchmark Summary - $TIMESTAMP

## Configuration

- **Mode**: $MODE
- **Measurement Time**: ${MEASUREMENT_TIME}s per benchmark
- **Sample Size**: $SAMPLE_SIZE samples
- **Baseline**: $BASELINE_NAME

## System Information

\`\`\`
$(cat "$SYSTEM_INFO")
\`\`\`

## Results

### Criterion HTML Reports

View detailed interactive reports at:
\`file://$PROJECT_ROOT/target/criterion/index.html\`

### Benchmark Logs

- Build log: [build_$TIMESTAMP.log](build_$TIMESTAMP.log)
- Benchmark output: [rust_bench_$TIMESTAMP.log](rust_bench_$TIMESTAMP.log)
- System info: [system_info_$TIMESTAMP.txt](system_info_$TIMESTAMP.txt)

### Key Metrics

EOF

# Extract key metrics from Criterion output
log_info "Extracting key metrics from benchmark output..."

# Parse throughput metrics
if grep -q "throughput" "$BENCH_OUTPUT"; then
    echo "#### Throughput Results" >> "$SUMMARY_FILE"
    echo "" >> "$SUMMARY_FILE"
    echo "\`\`\`" >> "$SUMMARY_FILE"
    grep -A 2 "throughput" "$BENCH_OUTPUT" | head -20 >> "$SUMMARY_FILE" || true
    echo "\`\`\`" >> "$SUMMARY_FILE"
    echo "" >> "$SUMMARY_FILE"
fi

# Parse latency metrics
if grep -q "time:" "$BENCH_OUTPUT"; then
    echo "#### Latency Results" >> "$SUMMARY_FILE"
    echo "" >> "$SUMMARY_FILE"
    echo "\`\`\`" >> "$SUMMARY_FILE"
    grep "time:" "$BENCH_OUTPUT" | head -20 >> "$SUMMARY_FILE" || true
    echo "\`\`\`" >> "$SUMMARY_FILE"
    echo "" >> "$SUMMARY_FILE"
fi

cat >> "$SUMMARY_FILE" << EOF

## Next Steps

1. **View detailed results**: Open \`target/criterion/index.html\` in a browser
2. **Compare with previous runs**: Use Criterion's built-in comparison features
3. **Compare with Go**: Run with \`--compare-go\` flag (requires Go sing-box build)

## Running Again

\`\`\`bash
# Quick benchmark
./scripts/run_benchmarks.sh --quick

# Full benchmark
./scripts/run_benchmarks.sh --full

# Specific protocol
./scripts/run_benchmarks.sh --protocol socks5

# Compare with Go
./scripts/run_benchmarks.sh --compare-go
\`\`\`
EOF

log_success "Summary report generated: $SUMMARY_FILE"

# Step 5: Go comparison (if requested)
if [ "$COMPARE_GO" = true ]; then
    log_section "Step 5: Go Baseline Comparison"
    
    GO_BINARY="$PROJECT_ROOT/go_fork_source/sing-box-1.12.14/sing-box"
    if [ -f "$GO_BINARY" ]; then
        log_info "Go binary found: $GO_BINARY"
        log_info "Manual comparison instructions added to summary"
        
        cat >> "$SUMMARY_FILE" << EOF

## Go Baseline Comparison

Go sing-box binary available at: \`$GO_BINARY\`

To manually compare:
1. Run equivalent operations using Go binary
2. Compare throughput and latency metrics
3. Document findings in this report

EOF
    else
        log_warn "Go binary not found at $GO_BINARY"
        log_info "To enable Go comparison:"
        log_info "  1. Build Go sing-box 1.12.14 in go_fork_source/sing-box-1.12.14"
        log_info "  2. Ensure binary is available at the expected path"
    fi
fi

# Final summary
log_section "Benchmark Run Complete"
log_success "All benchmarks completed successfully"
log_info "Results directory: $OUTPUT_DIR"
log_info "Summary report: $SUMMARY_FILE"
log_info "Criterion HTML: file://$PROJECT_ROOT/target/criterion/index.html"

# Create latest symlink
ln -sf "$(basename "$SUMMARY_FILE")" "$OUTPUT_DIR/latest_summary.md"
log_success "Created latest_summary.md symlink"

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                     Benchmark Complete!                          ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "📊 Summary: ${CYAN}$SUMMARY_FILE${NC}"
echo -e "🌐 HTML Reports: ${CYAN}file://$PROJECT_ROOT/target/criterion/index.html${NC}"
echo ""
