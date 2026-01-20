#!/usr/bin/env bash
#
# VEIL Client Build Script
#
# This script builds the VEIL client with configurable options.
# It can build with or without GUI support.
#
# Usage:
#   ./build_client.sh [OPTIONS]
#
# Options:
#   --with-gui          Build client with Qt6 GUI support
#   --build=TYPE        Build type: 'debug' or 'release' (default: release)
#   --clean             Clean build directory before building
#   --install           Install binaries to /usr/local/bin after building
#   --help              Show this help message
#
# Examples:
#   # Build client without GUI (CLI only)
#   ./build_client.sh
#
#   # Build client with Qt6 GUI
#   ./build_client.sh --with-gui
#
#   # Build debug version with GUI
#   ./build_client.sh --with-gui --build=debug
#
#   # Clean build and install
#   ./build_client.sh --with-gui --clean --install
#

set -e  # Exit on error
set -u  # Exit on undefined variable
set -o pipefail  # Exit on pipe failure

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration variables
BUILD_TYPE="${BUILD_TYPE:-release}"
WITH_GUI="${WITH_GUI:-false}"
CLEAN_BUILD="${CLEAN_BUILD:-false}"
INSTALL_BINARIES="${INSTALL_BINARIES:-false}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build/${BUILD_TYPE}"

# Functions for colored output
log_info() {
    echo -e "${BLUE}[INFO]${NC} $*"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

log_step() {
    echo -e "${CYAN}[STEP]${NC} ${BOLD}$*${NC}"
}

# Show usage/help
show_help() {
    cat << 'EOF'
VEIL Client Build Script

USAGE:
    ./build_client.sh [OPTIONS]

OPTIONS:
    --with-gui          Build client with Qt6 GUI support
    --build=TYPE        Build type: 'debug' or 'release' (default: release)
    --clean             Clean build directory before building
    --install           Install binaries to /usr/local/bin (requires sudo)
    --help              Show this help message

EXAMPLES:
    # Build CLI-only client (no GUI)
    ./build_client.sh

    # Build client with Qt6 GUI
    ./build_client.sh --with-gui

    # Debug build with GUI
    ./build_client.sh --with-gui --build=debug

    # Clean build and install
    ./build_client.sh --with-gui --clean --install

PREREQUISITES:
    - CMake 3.20+
    - C++20 compatible compiler (GCC 11+ or Clang 14+)
    - libsodium
    - Qt6 (optional, only if building with --with-gui)

INSTALL DEPENDENCIES (Ubuntu/Debian):
    # Base dependencies
    sudo apt-get install build-essential cmake libsodium-dev pkg-config git ninja-build

    # Qt6 (for GUI builds)
    sudo apt-get install qt6-base-dev

For more information, visit: https://github.com/VisageDvachevsky/veil
EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --build=*)
                BUILD_TYPE="${1#*=}"
                if [[ "$BUILD_TYPE" != "debug" && "$BUILD_TYPE" != "release" ]]; then
                    log_error "Invalid build type: $BUILD_TYPE (must be 'debug' or 'release')"
                    exit 1
                fi
                BUILD_DIR="${SCRIPT_DIR}/build/${BUILD_TYPE}"
                ;;
            --with-gui)
                WITH_GUI="true"
                ;;
            --clean)
                CLEAN_BUILD="true"
                ;;
            --install)
                INSTALL_BINARIES="true"
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                log_info "Use --help for usage information"
                exit 1
                ;;
        esac
        shift
    done
}

# Check for required tools
check_prerequisites() {
    log_step "Checking prerequisites..."

    local missing_tools=()

    # Check for CMake
    if ! command -v cmake >/dev/null 2>&1; then
        missing_tools+=("cmake")
    fi

    # Check for C++ compiler
    if ! command -v g++ >/dev/null 2>&1 && ! command -v clang++ >/dev/null 2>&1; then
        missing_tools+=("g++ or clang++")
    fi

    # Check for pkg-config
    if ! command -v pkg-config >/dev/null 2>&1; then
        missing_tools+=("pkg-config")
    fi

    # Check for libsodium
    if ! pkg-config --exists libsodium 2>/dev/null; then
        missing_tools+=("libsodium-dev")
    fi

    # Check for Qt6 if GUI is requested
    if [[ "$WITH_GUI" == "true" ]]; then
        if ! pkg-config --exists Qt6Core 2>/dev/null; then
            log_warn "Qt6 not found. GUI build may fail."
            log_warn "Install Qt6 with: sudo apt-get install qt6-base-dev"
        fi
    fi

    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        log_error "Missing required tools/libraries:"
        for tool in "${missing_tools[@]}"; do
            echo "  - $tool"
        done
        echo ""
        log_info "Install missing dependencies with:"
        echo "  sudo apt-get install build-essential cmake libsodium-dev pkg-config git ninja-build"
        exit 1
    fi

    log_success "All prerequisites met"
}

# Clean build directory
clean_build_dir() {
    if [[ "$CLEAN_BUILD" == "true" ]]; then
        log_step "Cleaning build directory..."
        if [[ -d "$BUILD_DIR" ]]; then
            rm -rf "$BUILD_DIR"
            log_success "Build directory cleaned"
        else
            log_info "Build directory does not exist, skipping clean"
        fi
    fi
}

# Configure CMake
configure_cmake() {
    log_step "Configuring CMake..."

    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"

    local cmake_opts=(
        "-DCMAKE_BUILD_TYPE=${BUILD_TYPE^}"  # Capitalize first letter
        "-DVEIL_BUILD_TESTS=OFF"
        "-GNinja"
    )

    # Enable/disable GUI build
    if [[ "$WITH_GUI" == "true" ]]; then
        cmake_opts+=("-DVEIL_BUILD_GUI=ON")
        log_info "Configuring with Qt6 GUI support..."
    else
        cmake_opts+=("-DVEIL_BUILD_GUI=OFF")
        log_info "Configuring without GUI (CLI only)..."
    fi

    log_info "Running CMake configuration..."
    cmake "${SCRIPT_DIR}" "${cmake_opts[@]}"

    log_success "CMake configuration complete"
}

# Build the client
build_client() {
    log_step "Building VEIL client..."

    cd "$BUILD_DIR"

    local num_cores
    num_cores=$(nproc 2>/dev/null || echo 4)

    log_info "Building with ${num_cores} parallel jobs..."
    cmake --build . --target veil-client -j"${num_cores}"

    # Build GUI client if requested
    if [[ "$WITH_GUI" == "true" ]]; then
        log_info "Building GUI client..."
        if cmake --build . --target veil-client-gui -j"${num_cores}" 2>/dev/null; then
            log_success "GUI client built successfully"
        else
            log_warn "GUI client build failed (Qt6 may not be available)"
            log_warn "CLI client was built successfully"
        fi
    fi

    log_success "Build complete"
}

# Display build results
show_build_results() {
    log_step "Build Results"

    echo ""
    echo -e "${GREEN}Built binaries:${NC}"

    if [[ -f "${BUILD_DIR}/src/veil-client" ]]; then
        echo -e "  ${GREEN}✓${NC} veil-client (CLI)"
        echo "    Location: ${BUILD_DIR}/src/veil-client"
    fi

    if [[ "$WITH_GUI" == "true" && -f "${BUILD_DIR}/src/gui-client/veil-client-gui" ]]; then
        echo -e "  ${GREEN}✓${NC} veil-client-gui (Qt6 GUI)"
        echo "    Location: ${BUILD_DIR}/src/gui-client/veil-client-gui"
    fi

    echo ""
}

# Install binaries
install_binaries() {
    if [[ "$INSTALL_BINARIES" != "true" ]]; then
        return
    fi

    log_step "Installing binaries..."

    if [[ $EUID -ne 0 ]]; then
        log_error "Installation requires root privileges"
        log_info "Run with sudo: sudo ./build_client.sh --install"
        exit 1
    fi

    cd "$BUILD_DIR"
    cmake --install . --prefix /usr/local

    log_success "Binaries installed to /usr/local/bin"
}

# Main build flow
main() {
    # Parse command line arguments first
    parse_args "$@"

    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                    VEIL Client Build Script                            ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    log_info "Build Configuration:"
    log_info "  Build Type: ${BUILD_TYPE}"
    log_info "  With GUI: ${WITH_GUI}"
    log_info "  Clean Build: ${CLEAN_BUILD}"
    log_info "  Install After Build: ${INSTALL_BINARIES}"
    echo ""

    check_prerequisites
    clean_build_dir
    configure_cmake
    build_client
    show_build_results
    install_binaries

    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                 Build Completed Successfully!                          ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    log_info "Next steps:"
    echo "  1. Run the client: ${BUILD_DIR}/src/veil-client --help"
    if [[ "$WITH_GUI" == "true" && -f "${BUILD_DIR}/src/gui-client/veil-client-gui" ]]; then
        echo "  2. Run the GUI client: ${BUILD_DIR}/src/gui-client/veil-client-gui"
    fi
    if [[ "$INSTALL_BINARIES" != "true" ]]; then
        echo "  3. Install system-wide: sudo ./build_client.sh --install"
    fi
    echo ""
}

# Run main function
main "$@"
