#!/bin/bash
#
# VEIL Transport Layer Network Emulation Test Script
#
# This script sets up network emulation (netem) on the loopback interface
# to simulate various network conditions for testing the transport layer.
#
# Usage:
#   sudo ./scripts/run_transport_netem.sh [setup|teardown|test] [profile]
#
# Profiles:
#   baseline   - No network emulation (baseline performance)
#   delay50    - 50ms delay with 10ms jitter
#   delay100   - 100ms delay with 20ms jitter
#   delay300   - 300ms delay with 30ms jitter (high latency)
#   loss5      - 5% packet loss
#   loss10     - 10% packet loss
#   loss20     - 20% packet loss (severe)
#   reorder    - 10% packet reordering
#   combined   - 50ms delay + 5% loss + 5% reorder (realistic bad network)
#
# Examples:
#   sudo ./scripts/run_transport_netem.sh setup delay50
#   ./build/debug/tests/transport_netem_test
#   sudo ./scripts/run_transport_netem.sh teardown
#
# Requirements:
#   - Root privileges (sudo)
#   - Linux with tc and netem support
#

set -e

INTERFACE="lo"
ACTION="${1:-help}"
PROFILE="${2:-delay50}"

show_help() {
    head -45 "$0" | tail -43
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo "Error: This script must be run as root (sudo)"
        exit 1
    fi
}

check_netem() {
    if ! modprobe -n -q sch_netem 2>/dev/null; then
        echo "Error: netem kernel module not available"
        exit 1
    fi
}

setup_netem() {
    local profile="$1"

    # Remove any existing qdisc
    tc qdisc del dev "$INTERFACE" root 2>/dev/null || true

    case "$profile" in
        baseline)
            echo "Setting up baseline (no emulation) on $INTERFACE"
            # No netem setup
            ;;
        delay50)
            echo "Setting up 50ms delay with 10ms jitter on $INTERFACE"
            tc qdisc add dev "$INTERFACE" root netem delay 50ms 10ms distribution normal
            ;;
        delay100)
            echo "Setting up 100ms delay with 20ms jitter on $INTERFACE"
            tc qdisc add dev "$INTERFACE" root netem delay 100ms 20ms distribution normal
            ;;
        delay300)
            echo "Setting up 300ms delay with 30ms jitter on $INTERFACE"
            tc qdisc add dev "$INTERFACE" root netem delay 300ms 30ms distribution normal
            ;;
        loss5)
            echo "Setting up 5% packet loss on $INTERFACE"
            tc qdisc add dev "$INTERFACE" root netem loss 5%
            ;;
        loss10)
            echo "Setting up 10% packet loss on $INTERFACE"
            tc qdisc add dev "$INTERFACE" root netem loss 10%
            ;;
        loss20)
            echo "Setting up 20% packet loss on $INTERFACE"
            tc qdisc add dev "$INTERFACE" root netem loss 20%
            ;;
        reorder)
            echo "Setting up 10% packet reordering on $INTERFACE"
            tc qdisc add dev "$INTERFACE" root netem delay 10ms reorder 90% 50%
            ;;
        combined)
            echo "Setting up combined (50ms delay + 5% loss + 5% reorder) on $INTERFACE"
            tc qdisc add dev "$INTERFACE" root netem delay 50ms 10ms loss 5% reorder 95% 50%
            ;;
        *)
            echo "Unknown profile: $profile"
            echo "Available profiles: baseline, delay50, delay100, delay300, loss5, loss10, loss20, reorder, combined"
            exit 1
            ;;
    esac

    echo "Network emulation configured:"
    tc qdisc show dev "$INTERFACE"
}

teardown_netem() {
    echo "Removing network emulation from $INTERFACE"
    tc qdisc del dev "$INTERFACE" root 2>/dev/null || true
    echo "Done"
}

show_status() {
    echo "Current qdisc configuration on $INTERFACE:"
    tc qdisc show dev "$INTERFACE"
}

run_tests() {
    local profile="${1:-combined}"
    local test_binary="${2:-./build/debug/tests/veil_tests}"

    check_root
    check_netem

    echo "=== Running VEIL transport netem tests ==="
    echo "Profile: $profile"
    echo "Test binary: $test_binary"
    echo ""

    # Setup netem
    setup_netem "$profile"

    # Run tests with VEIL_NETEM_PROFILE environment variable
    echo ""
    echo "Running tests..."
    VEIL_NETEM_PROFILE="$profile" "$test_binary" --gtest_filter="*TransportNetem*" || {
        local exit_code=$?
        echo "Tests failed with exit code: $exit_code"
        teardown_netem
        exit $exit_code
    }

    # Teardown netem
    teardown_netem

    echo ""
    echo "=== Tests completed successfully ==="
}

case "$ACTION" in
    setup)
        check_root
        check_netem
        setup_netem "$PROFILE"
        ;;
    teardown)
        check_root
        teardown_netem
        ;;
    status)
        show_status
        ;;
    test)
        run_tests "$PROFILE" "${3:-./build/debug/tests/veil_tests}"
        ;;
    help|--help|-h)
        show_help
        ;;
    *)
        echo "Unknown action: $ACTION"
        echo "Use: setup, teardown, status, test, or help"
        exit 1
        ;;
esac
