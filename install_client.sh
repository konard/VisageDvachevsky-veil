#!/usr/bin/env bash
#
# VEIL Client One-Line Automated Installer
#
# This script performs a complete automated installation and configuration
# of VEIL Client on Ubuntu/Debian systems with optional Qt6 GUI.
#
# One-line install:
#   curl -sSL https://raw.githubusercontent.com/VisageDvachevsky/veil/main/install_client.sh | sudo bash
#
#   With GUI:
#   curl -sSL https://raw.githubusercontent.com/VisageDvachevsky/veil/main/install_client.sh | sudo bash -s -- --with-gui
#
# Or download and run manually:
#   wget https://raw.githubusercontent.com/VisageDvachevsky/veil/main/install_client.sh
#   chmod +x install_client.sh
#   sudo ./install_client.sh [OPTIONS]
#
# Options:
#   --build=debug|release  Build type (default: release)
#   --with-gui             Install Qt6 GUI client
#   --no-service           Don't create/start systemd service
#   --dry-run              Show what would be done without making changes
#   --help                 Show this help message
#
# Examples:
#   # Install CLI-only client
#   curl -sSL https://...install_client.sh | sudo bash
#
#   # Install client with Qt6 GUI
#   curl -sSL https://...install_client.sh | sudo bash -s -- --with-gui
#
#   # Install with debug build
#   curl -sSL https://...install_client.sh | sudo bash -s -- --build=debug --with-gui
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
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration variables
VEIL_REPO="${VEIL_REPO:-https://github.com/VisageDvachevsky/veil.git}"
VEIL_BRANCH="${VEIL_BRANCH:-main}"
INSTALL_DIR="/usr/local"
CONFIG_DIR="/etc/veil"
BUILD_DIR="/tmp/veil-client-build-$$"
LOG_DIR="/var/log/veil"

# Installation options (can be overridden via command line)
BUILD_TYPE="${BUILD_TYPE:-release}"       # debug or release
WITH_GUI="${WITH_GUI:-false}"             # Install Qt6 GUI
CREATE_SERVICE="${CREATE_SERVICE:-true}"  # Create systemd service
DRY_RUN="${DRY_RUN:-false}"               # Dry run mode
VERBOSE="${VERBOSE:-false}"               # Verbose output

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

log_debug() {
    if [[ "$VERBOSE" == "true" ]]; then
        echo -e "${CYAN}[DEBUG]${NC} $*"
    fi
}

log_step() {
    echo -e "${MAGENTA}[STEP]${NC} ${BOLD}$*${NC}"
}

# Execute command or show in dry-run mode
run_cmd() {
    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "${YELLOW}[DRY-RUN]${NC} Would execute: $*"
        return 0
    fi
    log_debug "Executing: $*"
    "$@"
}

# Show usage/help
show_help() {
    cat << 'EOF'
VEIL Client One-Line Automated Installer

USAGE:
    curl -sSL https://raw.githubusercontent.com/VisageDvachevsky/veil/main/install_client.sh | sudo bash
    curl -sSL https://raw.githubusercontent.com/VisageDvachevsky/veil/main/install_client.sh | sudo bash -s -- [OPTIONS]

    Or download and run:
    ./install_client.sh [OPTIONS]

OPTIONS:
    --build=TYPE        Build type: 'debug' or 'release' (default: release)
    --with-gui          Install Qt6 GUI client
    --no-service        Skip systemd service creation (useful for containers)
    --dry-run           Show what would be done without making changes
    --verbose           Enable verbose output
    --help              Show this help message

ENVIRONMENT VARIABLES:
    VEIL_REPO           Git repository URL (default: https://github.com/VisageDvachevsky/veil.git)
    VEIL_BRANCH         Git branch to use (default: main)
    BUILD_TYPE          Same as --build
    WITH_GUI            Set to 'true' for GUI installation

EXAMPLES:
    # Basic CLI-only client installation
    curl -sSL https://...install_client.sh | sudo bash

    # Client with Qt6 GUI
    curl -sSL https://...install_client.sh | sudo bash -s -- --with-gui

    # Development setup with debug build and GUI
    curl -sSL https://...install_client.sh | sudo bash -s -- --build=debug --with-gui --verbose

    # Preview what would be installed
    curl -sSL https://...install_client.sh | sudo bash -s -- --dry-run --with-gui

GUI FEATURES (--with-gui):
    • Connection status monitoring
    • Real-time traffic statistics
    • Settings management interface
    • Diagnostics and logs viewer
    • Connection management

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
                ;;
            --with-gui)
                WITH_GUI="true"
                ;;
            --no-service)
                CREATE_SERVICE="false"
                ;;
            --dry-run)
                DRY_RUN="true"
                ;;
            --verbose)
                VERBOSE="true"
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

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        if [[ "$DRY_RUN" == "true" ]]; then
            log_warn "Not running as root (dry-run mode continues anyway)"
        else
            log_error "This script must be run as root (use sudo)"
            exit 1
        fi
    fi
}

# Detect OS and package manager
detect_os() {
    log_info "Detecting operating system..."

    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        OS_VERSION=$VERSION_ID
        log_info "Detected: $NAME $VERSION"
    else
        log_error "Cannot detect OS. /etc/os-release not found."
        exit 1
    fi

    case "$OS" in
        ubuntu|debian)
            PKG_MANAGER="apt-get"
            PKG_UPDATE="apt-get update"
            PKG_INSTALL="apt-get install -y"
            ;;
        centos|rhel|fedora)
            PKG_MANAGER="yum"
            PKG_UPDATE="yum check-update || true"
            PKG_INSTALL="yum install -y"
            ;;
        *)
            log_error "Unsupported OS: $OS"
            log_error "This installer supports Ubuntu, Debian, CentOS, RHEL, and Fedora"
            exit 1
            ;;
    esac
}

# Install build dependencies
install_dependencies() {
    log_step "Installing build dependencies..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would update package lists"
        log_info "[DRY-RUN] Would install: build-essential cmake libsodium-dev pkg-config git ninja-build"
        if [[ "$WITH_GUI" == "true" ]]; then
            log_info "[DRY-RUN] Would install Qt6 packages: qt6-base-dev"
        fi
        return
    fi

    run_cmd $PKG_UPDATE

    # Base packages needed for all builds
    local base_packages=""
    local qt_packages=""

    case "$OS" in
        ubuntu|debian)
            base_packages="build-essential cmake libsodium-dev pkg-config git ca-certificates curl ninja-build"
            qt_packages="qt6-base-dev"
            ;;
        centos|rhel|fedora)
            base_packages="gcc-c++ cmake libsodium-devel pkgconfig git ca-certificates curl ninja-build"
            qt_packages="qt6-qtbase-devel"
            ;;
    esac

    log_info "Installing base build tools..."
    # shellcheck disable=SC2086
    run_cmd $PKG_INSTALL $base_packages

    if [[ "$WITH_GUI" == "true" ]]; then
        log_info "Installing Qt6 packages for GUI..."
        # shellcheck disable=SC2086
        if ! run_cmd $PKG_INSTALL $qt_packages 2>/dev/null; then
            log_warn "Qt6 packages not available in default repositories"
            log_warn "Attempting to install from alternative sources..."

            case "$OS" in
                ubuntu)
                    # Try enabling universe repository for Ubuntu
                    run_cmd add-apt-repository -y universe 2>/dev/null || true
                    run_cmd $PKG_UPDATE
                    # shellcheck disable=SC2086
                    run_cmd $PKG_INSTALL $qt_packages || {
                        log_error "Failed to install Qt6. GUI will not be available."
                        log_warn "You can try installing Qt6 manually: sudo apt install qt6-base-dev"
                        WITH_GUI="false"
                    }
                    ;;
                *)
                    log_error "Qt6 installation failed. GUI will not be available."
                    WITH_GUI="false"
                    ;;
            esac
        fi
    fi

    log_success "Dependencies installed successfully"
}

# Clone and build VEIL client from source
build_veil_client() {
    log_step "Building VEIL client from source..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would clone $VEIL_REPO (branch: $VEIL_BRANCH)"
        log_info "[DRY-RUN] Would build with: BUILD_TYPE=$BUILD_TYPE, WITH_GUI=$WITH_GUI"
        log_info "[DRY-RUN] Would install binaries to $INSTALL_DIR/bin"
        return
    fi

    log_info "Cloning VEIL repository..."

    # Clean up previous build directory if exists
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"

    run_cmd git clone --depth 1 --branch "$VEIL_BRANCH" "$VEIL_REPO" "$BUILD_DIR"
    cd "$BUILD_DIR"

    log_info "Building VEIL client ($BUILD_TYPE mode)..."

    # Determine CMake options
    local cmake_opts=(
        "-DCMAKE_BUILD_TYPE=${BUILD_TYPE^}"  # Capitalize first letter
        "-DVEIL_BUILD_TESTS=OFF"
        "-DVEIL_BUILD_SERVER=OFF"  # Don't build server when installing client
        "-GNinja"
    )

    # Enable/disable GUI build
    if [[ "$WITH_GUI" == "true" ]]; then
        cmake_opts+=("-DVEIL_BUILD_GUI=ON")
        log_info "Building with Qt6 GUI support..."
    else
        cmake_opts+=("-DVEIL_BUILD_GUI=OFF")
    fi

    # Configure build directory
    local build_subdir="build/${BUILD_TYPE}"
    mkdir -p "$build_subdir"
    cd "$build_subdir"

    # Run CMake configure
    log_info "Configuring build..."
    run_cmd cmake ../.. "${cmake_opts[@]}"

    # Build client only
    log_info "Compiling client (this may take a few minutes)..."
    run_cmd cmake --build . --target veil-client -j"$(nproc)"

    # Build GUI client if requested
    if [[ "$WITH_GUI" == "true" ]]; then
        log_info "Compiling GUI client..."
        if run_cmd cmake --build . --target veil-client-gui -j"$(nproc)" 2>/dev/null; then
            log_success "GUI client built successfully"
        else
            log_warn "GUI client build failed (Qt6 may not be available)"
            WITH_GUI="false"
        fi
    fi

    # Install
    log_info "Installing VEIL client binaries..."
    run_cmd cmake --install . --prefix "$INSTALL_DIR"

    # Create log directory
    run_cmd mkdir -p "$LOG_DIR"
    run_cmd chmod 755 "$LOG_DIR"

    log_success "VEIL client built and installed to $INSTALL_DIR/bin"

    # Show what was installed
    log_info "Installed binaries:"
    ls -la "$INSTALL_DIR/bin/veil-client"* 2>/dev/null || true
}

# Create client configuration
create_client_config() {
    log_step "Creating client configuration..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would create client configuration at $CONFIG_DIR/client.conf"
        return
    fi

    run_cmd mkdir -p "$CONFIG_DIR"
    run_cmd chmod 700 "$CONFIG_DIR"

    if [[ -f "$CONFIG_DIR/client.conf" ]]; then
        log_warn "Configuration file already exists, backing up"
        run_cmd cp "$CONFIG_DIR/client.conf" "$CONFIG_DIR/client.conf.backup.$(date +%s)"
    fi

    cat > "$CONFIG_DIR/client.conf" <<EOF
# VEIL Client Configuration
# Auto-generated by install_client.sh on $(date)

[client]
# Server connection settings - EDIT THESE
server_address = <YOUR_SERVER_IP>
server_port = 4433

# Auto-reconnect settings
auto_reconnect = true
reconnect_delay_sec = 5
max_reconnect_attempts = 10

[tun]
device_name = veil0
mtu = 1400

[crypto]
preshared_key_file = $CONFIG_DIR/client.key

[obfuscation]
profile_seed_file = $CONFIG_DIR/obfuscation.seed

[logging]
level = info
log_file = $LOG_DIR/veil-client.log
EOF

    run_cmd chmod 600 "$CONFIG_DIR/client.conf"
    log_success "Client configuration created: $CONFIG_DIR/client.conf"
}

# Create systemd service
create_systemd_service() {
    if [[ "$CREATE_SERVICE" != "true" ]]; then
        log_info "Skipping systemd service creation (--no-service)"
        return
    fi

    log_step "Creating systemd service..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would create /etc/systemd/system/veil-client.service"
        return
    fi

    cat > "/etc/systemd/system/veil-client.service" <<EOF
[Unit]
Description=VEIL VPN Client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/bin/veil-client --config ${CONFIG_DIR}/client.conf
Restart=on-failure
RestartSec=5
User=root
Group=root

# Security hardening
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/run /var/log ${LOG_DIR}
NoNewPrivileges=true

# Resource limits
LimitNOFILE=65536
LimitNPROC=512

[Install]
WantedBy=multi-user.target
EOF

    run_cmd systemctl daemon-reload
    log_success "Systemd service created: veil-client.service"

    # Also create GUI service if GUI is installed
    if [[ "$WITH_GUI" == "true" ]]; then
        create_gui_service
    fi
}

# Create GUI application service (optional)
create_gui_service() {
    local gui_binary="${INSTALL_DIR}/bin/veil-client-gui"

    # Check if GUI binary exists
    if [[ ! -f "$gui_binary" ]]; then
        log_warn "GUI binary not found at $gui_binary, skipping GUI service"
        return
    fi

    log_info "Creating GUI service..."

    cat > "/etc/systemd/system/veil-client-gui.service" <<EOF
[Unit]
Description=VEIL VPN Client GUI Monitor
After=network-online.target veil-client.service
Wants=veil-client.service

[Service]
Type=simple
ExecStart=${gui_binary}
Restart=on-failure
RestartSec=5
# GUI needs display access
Environment=DISPLAY=:0
Environment=QT_QPA_PLATFORM=xcb

[Install]
WantedBy=graphical.target
EOF

    run_cmd systemctl daemon-reload
    log_success "GUI service created: veil-client-gui.service"
}

# Display summary and next steps
display_summary() {
    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              VEIL Client Installation Complete                         ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "This was a dry run - no changes were made"
        echo ""
        return
    fi

    echo -e "${BLUE}Installation Summary:${NC}"
    echo "  • Build Type: ${BUILD_TYPE}"
    echo "  • GUI Installed: ${WITH_GUI}"
    echo "  • Service Created: ${CREATE_SERVICE}"
    echo ""

    log_success "Client is ready for connection"
    echo ""
    echo -e "${BLUE}Configuration Files:${NC}"
    echo "  • Config: $CONFIG_DIR/client.conf"
    echo ""
    echo -e "${YELLOW}⚠ IMPORTANT - Before Connecting:${NC}"
    echo ""
    echo "You need the following files from your VEIL server:"
    echo "  1. server.key → $CONFIG_DIR/client.key"
    echo "  2. obfuscation.seed → $CONFIG_DIR/obfuscation.seed"
    echo ""
    echo "Example secure transfer from server:"
    echo "  scp user@server:/etc/veil/server.key $CONFIG_DIR/client.key"
    echo "  scp user@server:/etc/veil/obfuscation.seed $CONFIG_DIR/obfuscation.seed"
    echo ""
    echo "Edit $CONFIG_DIR/client.conf and set:"
    echo "  • server_address = <YOUR_SERVER_IP>"
    echo "  • server_port = 4433"
    echo ""

    if [[ "$CREATE_SERVICE" == "true" ]]; then
        echo -e "${BLUE}Management Commands:${NC}"
        echo "  • Start client:  sudo systemctl start veil-client"
        echo "  • Check status:  sudo systemctl status veil-client"
        echo "  • View logs:     sudo journalctl -u veil-client -f"
        echo "  • Restart:       sudo systemctl restart veil-client"
        echo "  • Stop:          sudo systemctl stop veil-client"
        echo "  • Enable auto-start: sudo systemctl enable veil-client"
    fi

    if [[ "$WITH_GUI" == "true" ]]; then
        echo ""
        echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║                      GUI Client Features                               ║${NC}"
        echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "${CYAN}GUI Features:${NC}"
        echo "  • Connection status monitoring"
        echo "  • Real-time traffic statistics"
        echo "  • Settings management interface"
        echo "  • Diagnostics and logs viewer"
        echo "  • Connection management"
        echo ""
        echo -e "${CYAN}Launch GUI:${NC}"
        echo "  • Manual: ${INSTALL_DIR}/bin/veil-client-gui"
        if [[ "$CREATE_SERVICE" == "true" ]]; then
            echo "  • Service: sudo systemctl start veil-client-gui"
        fi
    fi

    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}                    Installation completed successfully!                    ${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════════════════${NC}"
    echo ""
}

# Cleanup function
cleanup() {
    if [[ -d "$BUILD_DIR" ]]; then
        log_info "Cleaning up build directory..."
        rm -rf "$BUILD_DIR"
    fi
}

# Main installation flow
main() {
    # Parse command line arguments first
    parse_args "$@"

    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║              VEIL Client One-Line Automated Installer                  ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    if [[ "$DRY_RUN" == "true" ]]; then
        echo -e "${YELLOW}╔════════════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║                        DRY RUN MODE ENABLED                            ║${NC}"
        echo -e "${YELLOW}║              No changes will be made to your system                    ║${NC}"
        echo -e "${YELLOW}╚════════════════════════════════════════════════════════════════════════╝${NC}"
        echo ""
    fi

    log_info "Installation Configuration:"
    log_info "  Build Type: ${BUILD_TYPE}"
    log_info "  With GUI: ${WITH_GUI}"
    log_info "  Create Service: ${CREATE_SERVICE}"
    echo ""

    # Set trap for cleanup
    trap cleanup EXIT

    # Installation steps
    check_root
    detect_os
    install_dependencies
    build_veil_client
    create_client_config
    create_systemd_service

    # Display summary
    display_summary

    log_success "Installation completed successfully!"
}

# Run main function
main "$@"
