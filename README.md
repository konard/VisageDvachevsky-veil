# VEIL

[![CI](https://github.com/VisageDvachevsky/veil/actions/workflows/ci.yml/badge.svg)](https://github.com/VisageDvachevsky/veil/actions/workflows/ci.yml)
[![Unit Tests](https://github.com/VisageDvachevsky/veil/actions/workflows/unit-tests.yml/badge.svg)](https://github.com/VisageDvachevsky/veil/actions/workflows/unit-tests.yml)
[![Integration Tests](https://github.com/VisageDvachevsky/veil/actions/workflows/integration-tests.yml/badge.svg)](https://github.com/VisageDvachevsky/veil/actions/workflows/integration-tests.yml)
[![Security Tests](https://github.com/VisageDvachevsky/veil/actions/workflows/security-tests.yml/badge.svg)](https://github.com/VisageDvachevsky/veil/actions/workflows/security-tests.yml)
[![Network Emulation](https://github.com/VisageDvachevsky/veil/actions/workflows/network-emulation.yml/badge.svg)](https://github.com/VisageDvachevsky/veil/actions/workflows/network-emulation.yml)

A secure UDP-based transport protocol with cryptographic handshakes and encrypted data transfer.

## Quick Installation

### One-Line Client Installer

Install VEIL client with a single command:

```bash
# Install CLI-only client
curl -sSL https://raw.githubusercontent.com/VisageDvachevsky/veil/main/install_client.sh | sudo bash

# Install client with Qt6 GUI
curl -sSL https://raw.githubusercontent.com/VisageDvachevsky/veil/main/install_client.sh | sudo bash -s -- --with-gui
```

### One-Line Server Installer

Install VEIL server with a single command:

```bash
# Install CLI-only server
curl -sSL https://raw.githubusercontent.com/VisageDvachevsky/veil/main/install_veil.sh | sudo bash

# Install server with Qt6 GUI monitoring dashboard
curl -sSL https://raw.githubusercontent.com/VisageDvachevsky/veil/main/install_veil.sh | sudo bash -s -- --with-gui
```

## Building from Source

### Prerequisites

- CMake 3.20+
- C++20 compatible compiler (GCC 11+ or Clang 14+)
- libsodium
- Qt6 (optional, for GUI applications)

### Build Client Script

Quick client build with configurable options:

```bash
# Build CLI-only client
./build_client.sh

# Build client with Qt6 GUI
./build_client.sh --with-gui

# Clean build and install
./build_client.sh --with-gui --clean --install
```

### Manual Build Commands

```bash
# Configure and build debug version
cmake --preset debug
cmake --build build/debug -j$(nproc)

# Configure and build release version
cmake --preset release
cmake --build build/release -j$(nproc)
```

## Testing

### Running Unit and Integration Tests

```bash
# Run all tests
ctest --preset debug --output-on-failure

# Run specific test suite
./build/debug/tests/unit/veil_unit_tests --gtest_filter="PacketTests.*"
./build/debug/tests/integration/veil_integration_transport
```

### Network Emulation Testing (netem)

The integration tests support network emulation via Linux TC (Traffic Control) for testing under realistic network conditions. Netem tests require root privileges.

#### Setup netem (requires root)

```bash
# Add 50ms delay with 10ms jitter on loopback
sudo tc qdisc add dev lo root netem delay 50ms 10ms

# Add 1% packet loss
sudo tc qdisc change dev lo root netem delay 50ms 10ms loss 1%

# Remove netem when done
sudo tc qdisc del dev lo root
```

#### Running netem tests

```bash
# Skip netem tests (default in CI)
export VEIL_SKIP_NETEM=1
ctest --preset debug

# Enable netem tests (requires root and netem setup)
unset VEIL_SKIP_NETEM
sudo ./build/debug/tests/integration/veil_integration_transport
```

## Project Structure

```
src/
├── common/
│   ├── config/         # Configuration parsing
│   ├── crypto/         # Cryptographic primitives (AEAD, HKDF)
│   ├── handshake/      # Handshake protocol implementation
│   ├── ipc/            # IPC protocol for GUI/daemon communication
│   ├── logging/        # Logging utilities
│   ├── packet/         # Packet builder and parser
│   └── utils/          # Utilities (random, rate limiting)
├── transport/
│   ├── mux/            # Multiplexing codec and retransmission
│   ├── session/        # Transport session management
│   └── udp_socket/     # UDP socket wrapper
├── client/             # CLI client application
├── server/             # CLI server application
├── gui-client/         # Qt-based GUI client (optional)
└── gui-server/         # Qt-based GUI server (optional)
tests/
├── unit/               # Unit tests
└── integration/        # Integration tests
```

## License

See LICENSE file.
