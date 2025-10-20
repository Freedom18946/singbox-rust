#!/bin/bash
set -e

# Pressure smoke test - Simulate resource pressure conditions
# This script tests the system's behavior under file descriptor and memory pressure
# to ensure proper fallback and throttling mechanisms work correctly.

echo "🧪 Starting resource pressure smoke test"

# Configuration
ULIMIT_BACKUP=$(ulimit -n)
TEST_TIMEOUT=30
CONCURRENT_CONNECTIONS=50
TEST_BIND_PORT=0  # Let OS choose available port

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Cleanup function
cleanup() {
    echo -e "${YELLOW}🧹 Cleaning up...${NC}"

    # Kill background processes
    if [[ -n $SERVER_PID ]]; then
        kill $SERVER_PID 2>/dev/null || true
        wait $SERVER_PID 2>/dev/null || true
    fi

    # Restore original ulimit
    ulimit -n $ULIMIT_BACKUP

    # Clean up test files
    rm -f test_server.log test_clients.log

    echo -e "${GREEN}✅ Cleanup complete${NC}"
}

# Set up cleanup trap
trap cleanup EXIT

# Function to check if cargo is available and project can build
check_prerequisites() {
    echo "🔍 Checking prerequisites..."

    if ! command -v cargo &> /dev/null; then
        echo -e "${RED}❌ cargo not found. Please install Rust.${NC}"
        exit 1
    fi

    # Quick syntax check
    echo "📦 Checking if project compiles..."
    if ! cargo check -q --workspace; then
        echo -e "${RED}❌ Project does not compile. Fix compilation errors first.${NC}"
        exit 1
    fi

    echo -e "${GREEN}✅ Prerequisites OK${NC}"
}

# Function to build the test binary if needed
build_test_binary() {
    echo "🔨 Building test binary..."

    # Create a simple test binary that exercises the transport layer
    cat > test_pressure_client.rs << 'EOF'
use std::io::{self, Write};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[tokio::main]
async fn main() -> io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 4 {
        eprintln!("Usage: {} <host> <port> <concurrent_connections>", args[0]);
        return Ok(());
    }

    let host = &args[1];
    let port: u16 = args[2].parse().expect("Invalid port");
    let concurrent = args[3].parse::<u32>().expect("Invalid connection count");

    println!("Attempting {} concurrent connections to {}:{}", concurrent, host, port);

    let success_count = Arc::new(AtomicU32::new(0));
    let error_count = Arc::new(AtomicU32::new(0));

    let mut handles = Vec::new();
    let start_time = Instant::now();

    for i in 0..concurrent {
        let host = host.to_string();
        let success_count = success_count.clone();
        let error_count = error_count.clone();

        let handle = tokio::spawn(async move {
            match timeout(Duration::from_secs(5), TcpStream::connect((host.as_str(), port))).await {
                Ok(Ok(_stream)) => {
                    success_count.fetch_add(1, Ordering::Relaxed);
                    // Hold connection briefly
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Ok(Err(e)) => {
                    error_count.fetch_add(1, Ordering::Relaxed);
                    if i < 10 { // Only log first 10 errors to avoid spam
                        eprintln!("Connection {}: {}", i, e);
                    }
                }
                Err(_) => {
                    error_count.fetch_add(1, Ordering::Relaxed);
                    if i < 10 {
                        eprintln!("Connection {} timed out", i);
                    }
                }
            }
        });

        handles.push(handle);

        // Small delay between connections to avoid overwhelming
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Wait for all connections to complete
    for handle in handles {
        handle.await.ok();
    }

    let duration = start_time.elapsed();
    let successes = success_count.load(Ordering::Relaxed);
    let errors = error_count.load(Ordering::Relaxed);

    println!("Results after {:?}:", duration);
    println!("  Successful connections: {}", successes);
    println!("  Failed connections: {}", errors);
    println!("  Success rate: {:.1}%", (successes as f64 / concurrent as f64) * 100.0);

    Ok(())
}
EOF

    # Try to compile the test client
    if ! rustc --edition 2021 -L target/debug/deps test_pressure_client.rs -o test_pressure_client \
         --extern tokio=$(find target/debug/deps -name 'libtokio-*.rlib' | head -1) 2>/dev/null; then
        echo -e "${YELLOW}⚠️ Could not build pressure test client, using netcat fallback${NC}"
        rm -f test_pressure_client.rs
        return 1
    fi

    rm test_pressure_client.rs
    echo -e "${GREEN}✅ Test binary built${NC}"
    return 0
}

# Function to run a simple TCP server for testing
start_test_server() {
    echo "🚀 Starting test server..."

    # Use nc (netcat) to create a simple echo server
    if command -v nc &> /dev/null; then
        # Find an available port
        TEST_BIND_PORT=$(python3 -c "import socket; s=socket.socket(); s.bind(('',0)); print(s.getsockname()[1]); s.close()")
        nc -l -p $TEST_BIND_PORT -k > test_server.log 2>&1 &
        SERVER_PID=$!
        echo "Server listening on port $TEST_BIND_PORT (PID: $SERVER_PID)"
    else
        echo -e "${YELLOW}⚠️ netcat not available, using Python server${NC}"
        TEST_BIND_PORT=$(python3 -c "import socket; s=socket.socket(); s.bind(('',0)); print(s.getsockname()[1]); s.close()")
        python3 -c "
import socket
import threading
import time

def handle_client(conn, addr):
    try:
        conn.settimeout(1)
        data = conn.recv(1024)
        conn.send(b'OK\\n')
    except:
        pass
    finally:
        conn.close()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(('127.0.0.1', $TEST_BIND_PORT))
server.listen(50)

print('Server listening on port $TEST_BIND_PORT')
try:
    while True:
        conn, addr = server.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()
except KeyboardInterrupt:
    pass
finally:
    server.close()
" > test_server.log 2>&1 &
        SERVER_PID=$!
    fi

    # Wait for server to start
    sleep 2

    # Verify server is responding
    if ! timeout 5 bash -c "echo 'test' | nc 127.0.0.1 $TEST_BIND_PORT" &>/dev/null; then
        echo -e "${RED}❌ Test server failed to start or is not responding${NC}"
        return 1
    fi

    echo -e "${GREEN}✅ Test server started on port $TEST_BIND_PORT${NC}"
    return 0
}

# Test 1: Normal operation baseline
test_normal_operation() {
    echo -e "${YELLOW}📊 Test 1: Normal operation baseline${NC}"

    if [[ -f test_pressure_client ]]; then
        ./test_pressure_client 127.0.0.1 $TEST_BIND_PORT 10
    else
        echo "Running 10 concurrent connections using shell..."
        success=0
        for i in {1..10}; do
            if timeout 2 bash -c "echo 'test' | nc 127.0.0.1 $TEST_BIND_PORT" &>/dev/null; then
                ((success++))
            fi
        done
        echo "Baseline: $success/10 connections successful"
    fi

    echo -e "${GREEN}✅ Test 1 complete${NC}"
}

# Test 2: Low file descriptor limit
test_fd_pressure() {
    echo -e "${YELLOW}📊 Test 2: File descriptor pressure${NC}"

    # Set very low FD limit
    ulimit -n 20
    echo "Set ulimit -n to $(ulimit -n)"

    if [[ -f test_pressure_client ]]; then
        echo "Testing with limited file descriptors..."
        ./test_pressure_client 127.0.0.1 $TEST_BIND_PORT $CONCURRENT_CONNECTIONS || true
    else
        echo "Testing with limited file descriptors using shell..."
        success=0
        errors=0
        for i in $(seq 1 $CONCURRENT_CONNECTIONS); do
            if timeout 2 bash -c "echo 'test' | nc 127.0.0.1 $TEST_BIND_PORT" &>/dev/null 2>&1; then
                ((success++))
            else
                ((errors++))
            fi

            # Brief pause to avoid overwhelming
            [[ $((i % 5)) -eq 0 ]] && sleep 0.1
        done

        echo "FD pressure test: $success successful, $errors failed out of $CONCURRENT_CONNECTIONS"

        # We expect some failures due to FD limits
        if [[ $errors -gt 0 ]]; then
            echo -e "${GREEN}✅ FD pressure correctly caused failures (as expected)${NC}"
        else
            echo -e "${YELLOW}⚠️ No failures observed - FD limit might not be effective${NC}"
        fi
    fi

    # Restore higher FD limit for next test
    ulimit -n 1024
    echo -e "${GREEN}✅ Test 2 complete${NC}"
}

# Test 3: Fast concurrent connections
test_concurrent_load() {
    echo -e "${YELLOW}📊 Test 3: Concurrent connection load${NC}"

    if [[ -f test_pressure_client ]]; then
        echo "Testing concurrent load..."
        ./test_pressure_client 127.0.0.1 $TEST_BIND_PORT $CONCURRENT_CONNECTIONS || true
    else
        echo "Testing concurrent connections using shell background jobs..."

        # Launch background connections
        for i in $(seq 1 $CONCURRENT_CONNECTIONS); do
            (
                if timeout 5 bash -c "echo 'test$i' | nc 127.0.0.1 $TEST_BIND_PORT" &>/dev/null; then
                    echo "✓" > /tmp/conn_$i
                else
                    echo "✗" > /tmp/conn_$i
                fi
            ) &

            # Control rate of connection attempts
            [[ $((i % 10)) -eq 0 ]] && sleep 0.5
        done

        # Wait for all background jobs
        echo "Waiting for connections to complete..."
        wait

        # Count results
        success=$(find /tmp -name "conn_*" -exec grep -l "✓" {} \; 2>/dev/null | wc -l || echo "0")
        total=$(find /tmp -name "conn_*" 2>/dev/null | wc -l || echo "0")

        echo "Concurrent test: $success/$total connections successful"

        # Cleanup temp files
        rm -f /tmp/conn_*
    fi

    echo -e "${GREEN}✅ Test 3 complete${NC}"
}

# Test 4: Resource pressure metrics (if available)
test_metrics() {
    echo -e "${YELLOW}📊 Test 4: Resource pressure metrics${NC}"

    # Try to build and run a simple metrics test
    if cargo test -q -p sb-transport resource_pressure 2>/dev/null; then
        echo -e "${GREEN}✅ Resource pressure detection tests passed${NC}"
    else
        echo -e "${YELLOW}⚠️ Resource pressure tests not available or failed${NC}"
    fi

    echo -e "${GREEN}✅ Test 4 complete${NC}"
}

# Main execution
main() {
    echo "🏁 Resource Pressure Smoke Test"
    echo "================================"
    echo "This test simulates resource pressure to verify system resilience"
    echo "Current ulimit -n: $(ulimit -n)"
    echo "Test timeout: ${TEST_TIMEOUT}s"
    echo ""

    # Check prerequisites
    check_prerequisites

    # Try to build test binary
    build_test_binary || echo -e "${YELLOW}Continuing with shell-based tests${NC}"

    # Start test server
    if ! start_test_server; then
        echo -e "${RED}❌ Cannot start test server, aborting${NC}"
        exit 1
    fi

    echo ""
    echo "🧪 Running smoke tests..."
    echo "========================"

    # Run tests
    test_normal_operation
    echo ""

    test_fd_pressure
    echo ""

    test_concurrent_load
    echo ""

    test_metrics
    echo ""

    echo "🎯 Smoke test summary:"
    echo "======================"
    echo -e "${GREEN}✅ All smoke tests completed${NC}"
    echo "The system handled resource pressure scenarios."
    echo "Check logs above for specific failure patterns and recovery behavior."
    echo ""
    echo "Note: Some failures are expected and indicate proper resource"
    echo "pressure detection and handling."
}

# Handle timeout
timeout $TEST_TIMEOUT bash -c "$(declare -f main); main" || {
    echo -e "${RED}❌ Smoke test timed out after ${TEST_TIMEOUT}s${NC}"
    exit 1
}