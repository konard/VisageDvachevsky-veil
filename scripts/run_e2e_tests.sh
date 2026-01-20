#!/bin/bash
# VEIL End-to-End Test Script
# Tests client-server tunnel functionality using network namespaces.
# Requires root privileges.

set -e

# Colors for output.
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test configuration.
SERVER_NS="veil_server"
CLIENT_NS="veil_client"
VETH_SERVER="veth_srv"
VETH_CLIENT="veth_cli"
SERVER_IP="192.168.100.1"
CLIENT_IP="192.168.100.2"
TUNNEL_SERVER_IP="10.8.0.1"
TUNNEL_CLIENT_IP="10.8.0.2"
SERVER_PORT=4433
BUILD_DIR="${BUILD_DIR:-build/debug}"

# Cleanup function.
cleanup() {
    echo -e "${YELLOW}Cleaning up...${NC}"

    # Kill server and client.
    pkill -f "veil-server" 2>/dev/null || true
    pkill -f "veil-client" 2>/dev/null || true

    # Remove namespaces.
    ip netns del "$SERVER_NS" 2>/dev/null || true
    ip netns del "$CLIENT_NS" 2>/dev/null || true

    # Remove temp files.
    rm -f /tmp/veil_test_*.key
    rm -f /tmp/veil_test_*.log
    rm -f /tmp/veil_test_*.pid

    echo -e "${GREEN}Cleanup complete.${NC}"
}

# Set trap for cleanup.
trap cleanup EXIT

# Check prerequisites.
check_prerequisites() {
    echo -e "${YELLOW}Checking prerequisites...${NC}"

    # Check for root.
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}This script must be run as root.${NC}"
        exit 1
    fi

    # Check for required binaries.
    for cmd in ip iptables curl; do
        if ! command -v "$cmd" &> /dev/null; then
            echo -e "${RED}Required command not found: $cmd${NC}"
            exit 1
        fi
    done

    # Check for VEIL binaries.
    if [[ ! -f "$BUILD_DIR/src/server/veil-server" ]]; then
        echo -e "${RED}veil-server not found. Please build first.${NC}"
        exit 1
    fi

    if [[ ! -f "$BUILD_DIR/src/client/veil-client" ]]; then
        echo -e "${RED}veil-client not found. Please build first.${NC}"
        exit 1
    fi

    echo -e "${GREEN}Prerequisites OK.${NC}"
}

# Setup network namespaces.
setup_namespaces() {
    echo -e "${YELLOW}Setting up network namespaces...${NC}"

    # Create namespaces.
    ip netns add "$SERVER_NS"
    ip netns add "$CLIENT_NS"

    # Create veth pair.
    ip link add "$VETH_SERVER" type veth peer name "$VETH_CLIENT"

    # Move interfaces to namespaces.
    ip link set "$VETH_SERVER" netns "$SERVER_NS"
    ip link set "$VETH_CLIENT" netns "$CLIENT_NS"

    # Configure server namespace.
    ip netns exec "$SERVER_NS" ip addr add "$SERVER_IP/24" dev "$VETH_SERVER"
    ip netns exec "$SERVER_NS" ip link set "$VETH_SERVER" up
    ip netns exec "$SERVER_NS" ip link set lo up

    # Configure client namespace.
    ip netns exec "$CLIENT_NS" ip addr add "$CLIENT_IP/24" dev "$VETH_CLIENT"
    ip netns exec "$CLIENT_NS" ip link set "$VETH_CLIENT" up
    ip netns exec "$CLIENT_NS" ip link set lo up

    echo -e "${GREEN}Network namespaces configured.${NC}"
}

# Generate test keys.
generate_keys() {
    echo -e "${YELLOW}Generating test keys...${NC}"

    head -c 32 /dev/urandom > /tmp/veil_test_server.key
    cp /tmp/veil_test_server.key /tmp/veil_test_client.key
    head -c 32 /dev/urandom > /tmp/veil_test_obfuscation.seed

    echo -e "${GREEN}Keys generated.${NC}"
}

# Start server.
start_server() {
    echo -e "${YELLOW}Starting VEIL server...${NC}"

    ip netns exec "$SERVER_NS" "$BUILD_DIR/src/server/veil-server" \
        --listen "$SERVER_IP" \
        --port "$SERVER_PORT" \
        --tun-ip "$TUNNEL_SERVER_IP" \
        --key /tmp/veil_test_server.key \
        --verbose \
        > /tmp/veil_test_server.log 2>&1 &

    echo $! > /tmp/veil_test_server.pid

    # Wait for server to start.
    sleep 2

    if ! ps -p $(cat /tmp/veil_test_server.pid) > /dev/null; then
        echo -e "${RED}Server failed to start. Check /tmp/veil_test_server.log${NC}"
        cat /tmp/veil_test_server.log
        exit 1
    fi

    echo -e "${GREEN}Server started (PID: $(cat /tmp/veil_test_server.pid)).${NC}"
}

# Start client.
start_client() {
    echo -e "${YELLOW}Starting VEIL client...${NC}"

    ip netns exec "$CLIENT_NS" "$BUILD_DIR/src/client/veil-client" \
        --server "$SERVER_IP" \
        --port "$SERVER_PORT" \
        --tun-ip "$TUNNEL_CLIENT_IP" \
        --key /tmp/veil_test_client.key \
        --verbose \
        > /tmp/veil_test_client.log 2>&1 &

    echo $! > /tmp/veil_test_client.pid

    # Wait for client to connect.
    sleep 3

    if ! ps -p $(cat /tmp/veil_test_client.pid) > /dev/null; then
        echo -e "${RED}Client failed to start. Check /tmp/veil_test_client.log${NC}"
        cat /tmp/veil_test_client.log
        exit 1
    fi

    echo -e "${GREEN}Client started (PID: $(cat /tmp/veil_test_client.pid)).${NC}"
}

# Test: Ping through tunnel.
test_ping() {
    echo -e "${YELLOW}Test: Ping through tunnel...${NC}"

    if ip netns exec "$CLIENT_NS" ping -c 3 -W 5 "$TUNNEL_SERVER_IP" > /dev/null 2>&1; then
        echo -e "${GREEN}PASS: Ping succeeded.${NC}"
        return 0
    else
        echo -e "${RED}FAIL: Ping failed.${NC}"
        return 1
    fi
}

# Test: TCP connection through tunnel.
test_tcp() {
    echo -e "${YELLOW}Test: TCP connection through tunnel...${NC}"

    # Start a simple TCP server in the server namespace.
    ip netns exec "$SERVER_NS" sh -c "echo 'Hello from VEIL' | nc -l -p 8080 &"
    sleep 1

    # Connect from client.
    result=$(ip netns exec "$CLIENT_NS" nc -w 5 "$TUNNEL_SERVER_IP" 8080 2>/dev/null || echo "FAIL")

    if [[ "$result" == "Hello from VEIL" ]]; then
        echo -e "${GREEN}PASS: TCP connection succeeded.${NC}"
        return 0
    else
        echo -e "${RED}FAIL: TCP connection failed.${NC}"
        return 1
    fi
}

# Test: Large file transfer.
test_large_transfer() {
    echo -e "${YELLOW}Test: Large file transfer...${NC}"

    # Create 1MB test file.
    dd if=/dev/urandom of=/tmp/veil_test_file bs=1M count=1 2>/dev/null

    # Start nc server.
    ip netns exec "$SERVER_NS" sh -c "nc -l -p 8081 > /tmp/veil_test_received &"
    sleep 1

    # Send file from client.
    ip netns exec "$CLIENT_NS" sh -c "cat /tmp/veil_test_file | nc -w 10 $TUNNEL_SERVER_IP 8081"
    sleep 2

    # Compare files.
    if cmp -s /tmp/veil_test_file /tmp/veil_test_received; then
        echo -e "${GREEN}PASS: Large file transfer succeeded.${NC}"
        rm -f /tmp/veil_test_file /tmp/veil_test_received
        return 0
    else
        echo -e "${RED}FAIL: Large file transfer failed.${NC}"
        rm -f /tmp/veil_test_file /tmp/veil_test_received
        return 1
    fi
}

# Main test runner.
run_tests() {
    local failed=0

    echo ""
    echo "========================================"
    echo "       VEIL End-to-End Tests"
    echo "========================================"
    echo ""

    check_prerequisites
    generate_keys
    setup_namespaces
    start_server
    start_client

    echo ""
    echo "========================================"
    echo "           Running Tests"
    echo "========================================"
    echo ""

    # Run tests.
    test_ping || ((failed++))
    test_tcp || ((failed++))
    test_large_transfer || ((failed++))

    echo ""
    echo "========================================"
    echo "           Test Results"
    echo "========================================"
    echo ""

    if [[ $failed -eq 0 ]]; then
        echo -e "${GREEN}All tests passed!${NC}"
        return 0
    else
        echo -e "${RED}$failed test(s) failed.${NC}"
        return 1
    fi
}

# Run if executed directly.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    run_tests
fi
