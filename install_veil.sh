#!/usr/bin/env bash
#
# VEIL One-Line Automated Installer
#
# This script performs a complete automated installation and configuration
# of VEIL Server/Client on Ubuntu/Debian systems with optional Qt6 GUI.
#
# One-line install:
#   curl -sSL https://raw.githubusercontent.com/VisageDvachevsky/veil/main/install_veil.sh | sudo bash
#
# Or download and run manually:
#   wget https://raw.githubusercontent.com/VisageDvachevsky/veil/main/install_veil.sh
#   chmod +x install_veil.sh
#   sudo ./install_veil.sh [OPTIONS]
#
# Options:
#   --mode=server|client   Installation mode (default: server)
#   --build=debug|release  Build type (default: release)
#   --with-gui             Install Qt6 GUI with monitoring dashboard
#   --no-service           Don't create/start systemd service
#   --dry-run              Show what would be done without making changes
#   --help                 Show this help message
#
# Examples:
#   # Install server with GUI (recommended for monitoring)
#   curl -sSL https://...install_veil.sh | sudo bash -s -- --with-gui
#
#   # Install client only
#   curl -sSL https://...install_veil.sh | sudo bash -s -- --mode=client
#
#   # Install with debug build for development
#   curl -sSL https://...install_veil.sh | sudo bash -s -- --build=debug --with-gui
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
BUILD_DIR="/tmp/veil-build-$$"
LOG_DIR="/var/log/veil"
EXTERNAL_INTERFACE=""

# Installation options (can be overridden via command line)
INSTALL_MODE="${INSTALL_MODE:-server}"    # server or client
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
VEIL One-Line Automated Installer

USAGE:
    curl -sSL https://raw.githubusercontent.com/VisageDvachevsky/veil/main/install_veil.sh | sudo bash
    curl -sSL https://raw.githubusercontent.com/VisageDvachevsky/veil/main/install_veil.sh | sudo bash -s -- [OPTIONS]

    Or download and run:
    ./install_veil.sh [OPTIONS]

OPTIONS:
    --mode=MODE         Installation mode: 'server' or 'client' (default: server)
    --build=TYPE        Build type: 'debug' or 'release' (default: release)
    --with-gui          Install Qt6 GUI with real-time monitoring dashboard
    --no-service        Skip systemd service creation (useful for containers)
    --dry-run           Show what would be done without making changes
    --verbose           Enable verbose output
    --help              Show this help message

ENVIRONMENT VARIABLES:
    VEIL_REPO           Git repository URL (default: https://github.com/VisageDvachevsky/veil.git)
    VEIL_BRANCH         Git branch to use (default: main)
    INSTALL_MODE        Same as --mode
    BUILD_TYPE          Same as --build
    WITH_GUI            Set to 'true' for GUI installation

EXAMPLES:
    # Basic server installation (CLI only)
    curl -sSL https://...install_veil.sh | sudo bash

    # Server with Qt6 GUI monitoring dashboard
    curl -sSL https://...install_veil.sh | sudo bash -s -- --with-gui

    # Client-only installation
    curl -sSL https://...install_veil.sh | sudo bash -s -- --mode=client

    # Development setup with debug build and GUI
    curl -sSL https://...install_veil.sh | sudo bash -s -- --build=debug --with-gui --verbose

    # Preview what would be installed
    curl -sSL https://...install_veil.sh | sudo bash -s -- --dry-run --with-gui

GUI FEATURES (--with-gui):
    • Real-time traffic monitoring with dynamic graphs
    • Protocol state visualization
    • Connected clients list with statistics
    • Live event log viewer
    • Performance metrics dashboard (CPU, memory, bandwidth)
    • Session management interface
    • Export diagnostics functionality

For more information, visit: https://github.com/VisageDvachevsky/veil
EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --mode=*)
                INSTALL_MODE="${1#*=}"
                if [[ "$INSTALL_MODE" != "server" && "$INSTALL_MODE" != "client" ]]; then
                    log_error "Invalid mode: $INSTALL_MODE (must be 'server' or 'client')"
                    exit 1
                fi
                ;;
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
            log_info "[DRY-RUN] Would install Qt6 packages: qt6-base-dev qt6-charts-dev"
        fi
        if [[ "$INSTALL_MODE" == "server" ]]; then
            log_info "[DRY-RUN] Would install: iptables iproute2"
        fi
        return
    fi

    run_cmd $PKG_UPDATE

    # Base packages needed for all builds
    local base_packages=""
    local qt_packages=""
    local network_packages=""

    case "$OS" in
        ubuntu|debian)
            base_packages="build-essential cmake libsodium-dev pkg-config git ca-certificates curl ninja-build"
            qt_packages="qt6-base-dev libqt6charts6-dev"
            network_packages="iptables iproute2"
            ;;
        centos|rhel|fedora)
            base_packages="gcc-c++ cmake libsodium-devel pkgconfig git ca-certificates curl ninja-build"
            qt_packages="qt6-qtbase-devel qt6-qtcharts-devel"
            network_packages="iptables iproute"
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

    if [[ "$INSTALL_MODE" == "server" ]]; then
        log_info "Installing network tools for server..."
        # shellcheck disable=SC2086
        run_cmd $PKG_INSTALL $network_packages
    fi

    log_success "Dependencies installed successfully"
}

# Clone and build VEIL from source
build_veil() {
    log_step "Building VEIL from source..."

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

    log_info "Building VEIL ($BUILD_TYPE mode)..."

    # Determine CMake options based on installation mode
    local cmake_opts=(
        "-DCMAKE_BUILD_TYPE=${BUILD_TYPE^}"  # Capitalize first letter
        "-DVEIL_BUILD_TESTS=OFF"
        "-GNinja"
    )

    # Enable/disable server build based on mode
    if [[ "$INSTALL_MODE" == "client" ]]; then
        cmake_opts+=("-DVEIL_BUILD_SERVER=OFF")
        log_info "Client mode: building client only..."
    else
        cmake_opts+=("-DVEIL_BUILD_SERVER=ON")
        log_info "Server mode: building both server and client..."
    fi

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

    # Build
    log_info "Compiling (this may take a few minutes)..."
    run_cmd cmake --build . -j"$(nproc)"

    # Install
    log_info "Installing VEIL binaries..."
    run_cmd cmake --install . --prefix "$INSTALL_DIR"

    # Create log directory
    run_cmd mkdir -p "$LOG_DIR"
    run_cmd chmod 755 "$LOG_DIR"

    log_success "VEIL built and installed to $INSTALL_DIR/bin"

    # Show what was installed
    log_info "Installed binaries:"
    if [[ "$INSTALL_MODE" == "server" ]]; then
        ls -la "$INSTALL_DIR/bin/veil-server"* 2>/dev/null || true
    else
        ls -la "$INSTALL_DIR/bin/veil-client"* 2>/dev/null || true
    fi
}

# Detect external network interface
detect_external_interface() {
    log_info "Detecting external network interface..."

    if [[ "$DRY_RUN" == "true" ]]; then
        EXTERNAL_INTERFACE="eth0"
        log_info "[DRY-RUN] Would auto-detect external interface (using eth0 as placeholder)"
        return
    fi

    # Try to find the default route interface
    EXTERNAL_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)

    if [[ -z "$EXTERNAL_INTERFACE" ]]; then
        log_warn "Could not auto-detect external interface"
        log_warn "Available interfaces:"
        ip -o link show | awk -F': ' '{print "  - " $2}'

        # Default to common interface names
        for iface in eth0 ens3 enp0s3 ens33; do
            if ip link show "$iface" &>/dev/null; then
                EXTERNAL_INTERFACE="$iface"
                log_warn "Using $EXTERNAL_INTERFACE (please verify this is correct)"
                break
            fi
        done

        if [[ -z "$EXTERNAL_INTERFACE" ]]; then
            log_error "Could not determine external interface"
            log_error "Please edit /etc/veil/server.conf manually and set 'external_interface'"
            EXTERNAL_INTERFACE="eth0"  # Fallback
        fi
    else
        log_success "External interface: $EXTERNAL_INTERFACE"
    fi
}

# Generate cryptographic keys
generate_keys() {
    log_step "Generating cryptographic keys..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would create directory $CONFIG_DIR"
        log_info "[DRY-RUN] Would generate pre-shared key: $CONFIG_DIR/server.key"
        log_info "[DRY-RUN] Would generate obfuscation seed: $CONFIG_DIR/obfuscation.seed"
        return
    fi

    run_cmd mkdir -p "$CONFIG_DIR"
    run_cmd chmod 700 "$CONFIG_DIR"

    # Generate pre-shared key (32 bytes)
    if [[ ! -f "$CONFIG_DIR/server.key" ]]; then
        head -c 32 /dev/urandom > "$CONFIG_DIR/server.key"
        run_cmd chmod 600 "$CONFIG_DIR/server.key"
        log_success "Generated pre-shared key: $CONFIG_DIR/server.key"
    else
        log_warn "Pre-shared key already exists, skipping generation"
    fi

    # Generate obfuscation seed (32 bytes)
    if [[ ! -f "$CONFIG_DIR/obfuscation.seed" ]]; then
        head -c 32 /dev/urandom > "$CONFIG_DIR/obfuscation.seed"
        run_cmd chmod 600 "$CONFIG_DIR/obfuscation.seed"
        log_success "Generated obfuscation seed: $CONFIG_DIR/obfuscation.seed"
    else
        log_warn "Obfuscation seed already exists, skipping generation"
    fi
}

# Create server configuration
create_config() {
    log_step "Creating server configuration..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would create server configuration at $CONFIG_DIR/server.conf"
        return
    fi

    if [[ -f "$CONFIG_DIR/server.conf" ]]; then
        log_warn "Configuration file already exists, backing up to server.conf.backup"
        run_cmd cp "$CONFIG_DIR/server.conf" "$CONFIG_DIR/server.conf.backup.$(date +%s)"
    fi

    cat > "$CONFIG_DIR/server.conf" <<EOF
# VEIL Server Configuration
# Auto-generated by install_veil.sh on $(date)

[server]
listen_address = 0.0.0.0
listen_port = 4433
daemon = false
verbose = false

[tun]
device_name = veil0
ip_address = 10.8.0.1
netmask = 255.255.255.0
mtu = 1400

[crypto]
preshared_key_file = $CONFIG_DIR/server.key

[obfuscation]
profile_seed_file = $CONFIG_DIR/obfuscation.seed

[nat]
external_interface = $EXTERNAL_INTERFACE
enable_forwarding = true
use_masquerade = true

[sessions]
max_clients = 256
session_timeout = 300
idle_warning_sec = 270
absolute_timeout_sec = 86400
max_memory_per_session_mb = 10
cleanup_interval = 60
drain_timeout_sec = 5

[ip_pool]
start = 10.8.0.2
end = 10.8.0.254

[daemon]
pid_file = /var/run/veil-server.pid

[rate_limiting]
per_client_bandwidth_mbps = 100
per_client_pps = 10000
burst_allowance_factor = 1.5
reconnect_limit_per_minute = 5
enable_traffic_shaping = true

[degradation]
cpu_threshold_percent = 80
memory_threshold_percent = 85
enable_graceful_degradation = true
escalation_delay_sec = 5
recovery_delay_sec = 10

[logging]
level = info
rate_limit_logs_per_sec = 100
sampling_rate = 0.01
async_logging = true
format = json

[migration]
enable_session_migration = true
migration_token_ttl_sec = 300
max_migrations_per_session = 5
migration_cooldown_sec = 10
EOF

    chmod 600 "$CONFIG_DIR/server.conf"
    log_success "Configuration created: $CONFIG_DIR/server.conf"
}

# Configure system networking
configure_networking() {
    log_step "Configuring system networking..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would enable IP forwarding"
        log_info "[DRY-RUN] Would add NAT/MASQUERADE rule for 10.8.0.0/24"
        return
    fi

    # Enable IP forwarding
    log_info "Enabling IP forwarding..."
    run_cmd sysctl -w net.ipv4.ip_forward=1 > /dev/null

    # Make it permanent
    if ! grep -q "net.ipv4.ip_forward.*=.*1" /etc/sysctl.conf 2>/dev/null; then
        echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
    fi

    log_success "IP forwarding enabled"

    # Configure NAT/MASQUERADE
    log_info "Configuring NAT (MASQUERADE)..."

    # Check if rule already exists
    if ! iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o "$EXTERNAL_INTERFACE" -j MASQUERADE 2>/dev/null; then
        run_cmd iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$EXTERNAL_INTERFACE" -j MASQUERADE
        log_success "NAT rule added"
    else
        log_warn "NAT rule already exists"
    fi

    # Save iptables rules
    case "$OS" in
        ubuntu|debian)
            if command -v iptables-save >/dev/null 2>&1; then
                if command -v netfilter-persistent >/dev/null 2>&1; then
                    netfilter-persistent save
                elif [[ -d /etc/iptables ]]; then
                    iptables-save > /etc/iptables/rules.v4
                fi
            fi
            ;;
        centos|rhel|fedora)
            if command -v iptables-save >/dev/null 2>&1; then
                iptables-save > /etc/sysconfig/iptables 2>/dev/null || true
            fi
            ;;
    esac

    log_success "Networking configured"
}

# Configure firewall
configure_firewall() {
    log_step "Configuring firewall..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would allow UDP port 4433 through firewall"
        return
    fi

    # Detect and configure firewall
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
        log_info "Detected UFW firewall"
        run_cmd ufw allow 4433/udp
        log_success "UFW: Allowed UDP port 4433"
    elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        log_info "Detected firewalld"
        run_cmd firewall-cmd --permanent --add-port=4433/udp
        run_cmd firewall-cmd --reload
        log_success "firewalld: Allowed UDP port 4433"
    else
        log_info "Configuring iptables directly..."
        if ! iptables -C INPUT -p udp --dport 4433 -j ACCEPT 2>/dev/null; then
            run_cmd iptables -A INPUT -p udp --dport 4433 -j ACCEPT
            log_success "iptables: Allowed UDP port 4433"
        else
            log_warn "Firewall rule already exists"
        fi
    fi
}

# Create systemd service
create_systemd_service() {
    if [[ "$CREATE_SERVICE" != "true" ]]; then
        log_info "Skipping systemd service creation (--no-service)"
        return
    fi

    log_step "Creating systemd service..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would create /etc/systemd/system/veil-${INSTALL_MODE}.service"
        return
    fi

    local service_name="veil-${INSTALL_MODE}"
    local binary_name="veil-${INSTALL_MODE}"
    local config_file="${CONFIG_DIR}/${INSTALL_MODE}.conf"

    cat > "/etc/systemd/system/${service_name}.service" <<EOF
[Unit]
Description=VEIL VPN ${INSTALL_MODE^}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/bin/${binary_name} --config ${config_file}
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
    log_success "Systemd service created: ${service_name}.service"

    # Also create GUI service if GUI is installed
    if [[ "$WITH_GUI" == "true" ]]; then
        create_gui_service
    fi
}

# Create GUI application service (optional)
create_gui_service() {
    local gui_service_name="veil-${INSTALL_MODE}-gui"
    local gui_binary="${INSTALL_DIR}/bin/veil-${INSTALL_MODE}-gui"

    # Check if GUI binary exists
    if [[ ! -f "$gui_binary" ]]; then
        log_warn "GUI binary not found at $gui_binary, skipping GUI service"
        return
    fi

    log_info "Creating GUI service..."

    cat > "/etc/systemd/system/${gui_service_name}.service" <<EOF
[Unit]
Description=VEIL VPN ${INSTALL_MODE^} GUI Monitor
After=network-online.target veil-${INSTALL_MODE}.service
Wants=veil-${INSTALL_MODE}.service

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
    log_success "GUI service created: ${gui_service_name}.service"
}

# Start and enable service
start_service() {
    if [[ "$CREATE_SERVICE" != "true" ]]; then
        log_info "Skipping service start (--no-service)"
        return
    fi

    local service_name="veil-${INSTALL_MODE}"

    log_step "Starting VEIL ${INSTALL_MODE} service..."

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "[DRY-RUN] Would enable and start ${service_name}.service"
        return
    fi

    run_cmd systemctl enable "$service_name"
    run_cmd systemctl start "$service_name"

    # Wait a moment for service to start
    sleep 2

    if systemctl is-active --quiet "$service_name"; then
        log_success "VEIL ${INSTALL_MODE} is running!"
    else
        log_error "Failed to start VEIL ${INSTALL_MODE}"
        log_error "Check logs with: sudo journalctl -u ${service_name} -n 50"
        exit 1
    fi
}

# Display summary and next steps
display_summary() {
    local public_ip
    public_ip=$(curl -s ifconfig.me 2>/dev/null || echo "<YOUR_SERVER_IP>")

    local service_name="veil-${INSTALL_MODE}"

    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              VEIL ${INSTALL_MODE^} Installation Complete                          ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    if [[ "$DRY_RUN" == "true" ]]; then
        log_info "This was a dry run - no changes were made"
        echo ""
        return
    fi

    echo -e "${BLUE}Installation Summary:${NC}"
    echo "  • Mode: ${INSTALL_MODE}"
    echo "  • Build Type: ${BUILD_TYPE}"
    echo "  • GUI Installed: ${WITH_GUI}"
    echo "  • Service Created: ${CREATE_SERVICE}"
    echo ""

    if [[ "$INSTALL_MODE" == "server" ]]; then
        log_success "Server is running and ready for client connections"
        echo ""
        echo -e "${BLUE}Server Information:${NC}"
        echo "  • Server Address: $public_ip"
        echo "  • Server Port: 4433 (UDP)"
        echo "  • Tunnel Network: 10.8.0.0/24"
        echo "  • Server Tunnel IP: 10.8.0.1"
        echo ""
        echo -e "${BLUE}Configuration Files:${NC}"
        echo "  • Config: $CONFIG_DIR/server.conf"
        echo "  • PSK: $CONFIG_DIR/server.key"
        echo "  • Obfuscation Seed: $CONFIG_DIR/obfuscation.seed"
        echo ""
        echo -e "${YELLOW}⚠ IMPORTANT - Client Setup:${NC}"
        echo ""
        echo "To connect clients, securely transfer these files to each client:"
        echo "  1. $CONFIG_DIR/server.key → /etc/veil/client.key"
        echo "  2. $CONFIG_DIR/obfuscation.seed → /etc/veil/obfuscation.seed"
        echo ""
        echo "Example secure transfer:"
        echo "  scp $CONFIG_DIR/server.key user@client:/etc/veil/client.key"
        echo "  scp $CONFIG_DIR/obfuscation.seed user@client:/etc/veil/"
        echo ""
        echo -e "${YELLOW}⚠ NEVER send these keys over email or insecure channels!${NC}"
        echo ""
        echo -e "${BLUE}Network Status:${NC}"
        echo "  • IP Forwarding: $(sysctl -n net.ipv4.ip_forward 2>/dev/null || echo 'N/A')"
        echo "  • External Interface: $EXTERNAL_INTERFACE"
    else
        log_success "Client is ready for connection"
        echo ""
        echo -e "${BLUE}Client Configuration:${NC}"
        echo "  • Config: $CONFIG_DIR/client.conf"
        echo ""
        echo -e "${YELLOW}⚠ IMPORTANT - Before Connecting:${NC}"
        echo ""
        echo "You need the following files from your VEIL server:"
        echo "  1. server.key → $CONFIG_DIR/client.key"
        echo "  2. obfuscation.seed → $CONFIG_DIR/obfuscation.seed"
        echo ""
        echo "Edit $CONFIG_DIR/client.conf and set:"
        echo "  • server_address = <YOUR_SERVER_IP>"
        echo "  • server_port = 4433"
    fi

    echo ""
    if [[ "$CREATE_SERVICE" == "true" ]]; then
        echo -e "${BLUE}Management Commands:${NC}"
        echo "  • Check status:  sudo systemctl status ${service_name}"
        echo "  • View logs:     sudo journalctl -u ${service_name} -f"
        echo "  • Restart:       sudo systemctl restart ${service_name}"
        echo "  • Stop:          sudo systemctl stop ${service_name}"
    fi

    if [[ "$WITH_GUI" == "true" ]]; then
        echo ""
        echo -e "${CYAN}╔════════════════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${CYAN}║                      GUI Monitoring Dashboard                          ║${NC}"
        echo -e "${CYAN}╚════════════════════════════════════════════════════════════════════════╝${NC}"
        echo ""
        echo -e "${CYAN}GUI Features:${NC}"
        echo "  • Real-time traffic monitoring with dynamic graphs"
        echo "  • Protocol state visualization"
        echo "  • Connected clients list with statistics"
        echo "  • Live event log viewer"
        echo "  • Performance metrics (CPU, memory, bandwidth)"
        echo "  • Export diagnostics functionality"
        echo ""
        echo -e "${CYAN}Launch GUI:${NC}"
        echo "  • Manual: ${INSTALL_DIR}/bin/veil-${INSTALL_MODE}-gui"
        if [[ "$CREATE_SERVICE" == "true" ]]; then
            echo "  • Service: sudo systemctl start veil-${INSTALL_MODE}-gui"
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
# Auto-generated by install_veil.sh on $(date)

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

# Main installation flow
main() {
    # Parse command line arguments first
    parse_args "$@"

    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║              VEIL One-Line Automated Installer v2.0                    ║${NC}"
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
    log_info "  Mode: ${INSTALL_MODE}"
    log_info "  Build Type: ${BUILD_TYPE}"
    log_info "  With GUI: ${WITH_GUI}"
    log_info "  Create Service: ${CREATE_SERVICE}"
    echo ""

    # Set trap for cleanup
    trap cleanup EXIT

    # Common installation steps
    check_root
    detect_os
    install_dependencies
    build_veil

    # Mode-specific installation
    if [[ "$INSTALL_MODE" == "server" ]]; then
        log_step "Configuring VEIL Server..."
        detect_external_interface
        generate_keys
        create_config
        configure_networking
        configure_firewall
    else
        log_step "Configuring VEIL Client..."
        create_client_config
    fi

    # Service setup (common)
    create_systemd_service
    start_service

    # Display summary
    display_summary

    log_success "Installation completed successfully!"
}

# Run main function
main "$@"
