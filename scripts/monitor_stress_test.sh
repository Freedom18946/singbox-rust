#!/bin/bash
# Monitor stress test execution
#
# This script monitors a running stress test and logs:
# - CPU and memory usage
# - File descriptor count
# - Network connections
# - System resources
#
# Usage:
#   ./scripts/monitor_stress_test.sh [PID]
#
# If PID is not provided, will search for bench_p0_protocols process

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INTERVAL=60  # Monitoring interval in seconds
LOG_DIR="reports/stress-tests"
LOG_FILE="$LOG_DIR/monitor_$(date +%Y%m%d_%H%M%S).log"

# Create log directory
mkdir -p "$LOG_DIR"

# Find process ID
if [ -n "$1" ]; then
    PID=$1
else
    PID=$(pgrep -f bench_p0_protocols | head -1)
    if [ -z "$PID" ]; then
        echo -e "${RED}Error: No bench_p0_protocols process found${NC}"
        echo "Usage: $0 [PID]"
        exit 1
    fi
fi

echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║          Stress Test Monitoring Started               ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}Monitoring PID: $PID${NC}"
echo -e "${GREEN}Log file: $LOG_FILE${NC}"
echo -e "${GREEN}Interval: ${INTERVAL}s${NC}"
echo ""

# Log header
{
    echo "==================================================================="
    echo "Stress Test Monitoring Log"
    echo "==================================================================="
    echo "PID: $PID"
    echo "Start time: $(date)"
    echo "Interval: ${INTERVAL}s"
    echo "==================================================================="
    echo ""
} | tee -a "$LOG_FILE"

# Initialize counters
ITERATION=0
MAX_MEMORY=0
MAX_FDS=0
MAX_CONNECTIONS=0

# Monitoring loop
while kill -0 $PID 2>/dev/null; do
    ITERATION=$((ITERATION + 1))
    TIMESTAMP=$(date '+%Y-%m-%d %H:%M:%S')
    
    # Get process stats
    if [ "$(uname)" = "Darwin" ]; then
        # macOS
        STATS=$(ps -p $PID -o %cpu,%mem,vsz,rss 2>/dev/null | tail -1)
        CPU=$(echo "$STATS" | awk '{print $1}')
        MEM=$(echo "$STATS" | awk '{print $2}')
        VSZ=$(echo "$STATS" | awk '{print $3}')
        RSS=$(echo "$STATS" | awk '{print $4}')
    else
        # Linux
        STATS=$(ps -p $PID -o %cpu,%mem,vsz,rss 2>/dev/null | tail -1)
        CPU=$(echo "$STATS" | awk '{print $1}')
        MEM=$(echo "$STATS" | awk '{print $2}')
        VSZ=$(echo "$STATS" | awk '{print $3}')
        RSS=$(echo "$STATS" | awk '{print $4}')
    fi
    
    # Get file descriptor count
    if command -v lsof >/dev/null 2>&1; then
        FDS=$(lsof -p $PID 2>/dev/null | wc -l | tr -d ' ')
    else
        FDS="N/A"
    fi
    
    # Get network connection count
    if [ "$(uname)" = "Darwin" ]; then
        CONNECTIONS=$(netstat -an 2>/dev/null | grep ESTABLISHED | wc -l | tr -d ' ')
    else
        CONNECTIONS=$(ss -tan 2>/dev/null | grep ESTAB | wc -l | tr -d ' ')
    fi
    
    # Update maximums
    if [ "$RSS" != "RSS" ] && [ -n "$RSS" ]; then
        if [ "$RSS" -gt "$MAX_MEMORY" ]; then
            MAX_MEMORY=$RSS
        fi
    fi
    
    if [ "$FDS" != "N/A" ] && [ -n "$FDS" ]; then
        if [ "$FDS" -gt "$MAX_FDS" ]; then
            MAX_FDS=$FDS
        fi
    fi
    
    if [ -n "$CONNECTIONS" ]; then
        if [ "$CONNECTIONS" -gt "$MAX_CONNECTIONS" ]; then
            MAX_CONNECTIONS=$CONNECTIONS
        fi
    fi
    
    # Log to file
    {
        echo "=== Iteration $ITERATION - $TIMESTAMP ==="
        echo "CPU: ${CPU}%"
        echo "Memory: ${MEM}% (RSS: ${RSS}KB, VSZ: ${VSZ}KB)"
        echo "File Descriptors: $FDS"
        echo "Network Connections: $CONNECTIONS"
        echo "Max Memory: ${MAX_MEMORY}KB"
        echo "Max FDs: $MAX_FDS"
        echo "Max Connections: $MAX_CONNECTIONS"
        echo ""
    } >> "$LOG_FILE"
    
    # Display to console
    echo -e "${YELLOW}[$TIMESTAMP] Iteration $ITERATION${NC}"
    echo -e "  CPU: ${CPU}%"
    echo -e "  Memory: ${MEM}% (${RSS}KB)"
    echo -e "  FDs: $FDS"
    echo -e "  Connections: $CONNECTIONS"
    
    # Check for issues
    if [ "$RSS" != "RSS" ] && [ -n "$RSS" ]; then
        if [ "$RSS" -gt 1048576 ]; then  # > 1GB
            echo -e "  ${RED}⚠ High memory usage!${NC}"
        fi
    fi
    
    if [ "$FDS" != "N/A" ] && [ -n "$FDS" ]; then
        if [ "$FDS" -gt 1000 ]; then
            echo -e "  ${RED}⚠ High FD count!${NC}"
        fi
    fi
    
    echo ""
    
    sleep $INTERVAL
done

# Process ended
END_TIME=$(date)
DURATION=$((ITERATION * INTERVAL))

echo -e "${BLUE}╔════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║          Stress Test Monitoring Completed             ║${NC}"
echo -e "${BLUE}╚════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${GREEN}End time: $END_TIME${NC}"
echo -e "${GREEN}Duration: ${DURATION}s ($(($DURATION / 60)) minutes)${NC}"
echo -e "${GREEN}Iterations: $ITERATION${NC}"
echo ""
echo -e "${YELLOW}Summary:${NC}"
echo -e "  Max Memory: ${MAX_MEMORY}KB"
echo -e "  Max FDs: $MAX_FDS"
echo -e "  Max Connections: $MAX_CONNECTIONS"
echo ""
echo -e "${GREEN}Log saved to: $LOG_FILE${NC}"

# Log summary
{
    echo "==================================================================="
    echo "Monitoring Summary"
    echo "==================================================================="
    echo "End time: $END_TIME"
    echo "Duration: ${DURATION}s"
    echo "Iterations: $ITERATION"
    echo "Max Memory: ${MAX_MEMORY}KB"
    echo "Max FDs: $MAX_FDS"
    echo "Max Connections: $MAX_CONNECTIONS"
    echo "==================================================================="
} >> "$LOG_FILE"

# Generate simple report
REPORT_FILE="$LOG_DIR/report_$(date +%Y%m%d_%H%M%S).txt"
{
    echo "Stress Test Report"
    echo "=================="
    echo ""
    echo "Test Duration: ${DURATION}s ($(($DURATION / 60)) minutes)"
    echo "Monitoring Iterations: $ITERATION"
    echo ""
    echo "Resource Usage:"
    echo "  Peak Memory: ${MAX_MEMORY}KB ($(($MAX_MEMORY / 1024))MB)"
    echo "  Peak File Descriptors: $MAX_FDS"
    echo "  Peak Connections: $MAX_CONNECTIONS"
    echo ""
    echo "Status: COMPLETED"
    echo ""
    echo "Detailed log: $LOG_FILE"
} > "$REPORT_FILE"

echo -e "${GREEN}Report saved to: $REPORT_FILE${NC}"
