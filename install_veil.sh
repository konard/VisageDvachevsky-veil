#!/usr/bin/env bash
#
# VEIL Server Automated Installer
#
# This script performs a complete automated installation and configuration
# of VEIL Server on Ubuntu/Debian systems.
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/VisageDvachevsky/veil-core/main/install_veil.sh | sudo bash
#
# Or download and run manually:
#   wget https://raw.githubusercontent.com/VisageDvachevsky/veil-core/main/install_veil.sh
#   chmod +x install_veil.sh
#   sudo ./install_veil.sh
#

set -e  # Exit on error
set -u  # Exit on undefined variable
set -o pipefail  # Exit on pipe failure

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration variables
VEIL_REPO="${VEIL_REPO:-https://github.com/VisageDvachevsky/veil-core.git}"
VEIL_BRANCH="${VEIL_BRANCH:-main}"
INSTALL_DIR="/usr/local"
CONFIG_DIR="/etc/veil"
BUILD_DIR="/tmp/veil-build-$$"
EXTERNAL_INTERFACE=""

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

# Check if running as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
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
    log_info "Installing build dependencies..."

    $PKG_UPDATE

    case "$OS" in
        ubuntu|debian)
            $PKG_INSTALL \
                build-essential \
                cmake \
                libsodium-dev \
                pkg-config \
                git \
                iptables \
                iproute2 \
                ca-certificates \
                curl
            ;;
        centos|rhel|fedora)
            $PKG_INSTALL \
                gcc-c++ \
                cmake \
                libsodium-devel \
                pkgconfig \
                git \
                iptables \
                iproute \
                ca-certificates \
                curl
            ;;
    esac

    log_success "Dependencies installed successfully"
}

# Clone and build VEIL from source
build_veil() {
    log_info "Cloning VEIL repository..."

    # Clean up previous build directory if exists
    rm -rf "$BUILD_DIR"
    mkdir -p "$BUILD_DIR"

    git clone --depth 1 --branch "$VEIL_BRANCH" "$VEIL_REPO" "$BUILD_DIR"
    cd "$BUILD_DIR"

    log_info "Building VEIL (this may take a few minutes)..."

    mkdir -p build
    cd build

    # Build without tests and tools for faster installation
    cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DVEIL_BUILD_TESTS=OFF \
        -DVEIL_BUILD_TOOLS=OFF

    make -j$(nproc)

    log_info "Installing VEIL binaries..."
    make install

    log_success "VEIL built and installed to $INSTALL_DIR/bin"
}

# Detect external network interface
detect_external_interface() {
    log_info "Detecting external network interface..."

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
    log_info "Generating cryptographic keys..."

    mkdir -p "$CONFIG_DIR"
    chmod 700 "$CONFIG_DIR"

    # Generate pre-shared key (32 bytes)
    if [[ ! -f "$CONFIG_DIR/server.key" ]]; then
        head -c 32 /dev/urandom > "$CONFIG_DIR/server.key"
        chmod 600 "$CONFIG_DIR/server.key"
        log_success "Generated pre-shared key: $CONFIG_DIR/server.key"
    else
        log_warn "Pre-shared key already exists, skipping generation"
    fi

    # Generate obfuscation seed (32 bytes)
    if [[ ! -f "$CONFIG_DIR/obfuscation.seed" ]]; then
        head -c 32 /dev/urandom > "$CONFIG_DIR/obfuscation.seed"
        chmod 600 "$CONFIG_DIR/obfuscation.seed"
        log_success "Generated obfuscation seed: $CONFIG_DIR/obfuscation.seed"
    else
        log_warn "Obfuscation seed already exists, skipping generation"
    fi
}

# Create server configuration
create_config() {
    log_info "Creating server configuration..."

    if [[ -f "$CONFIG_DIR/server.conf" ]]; then
        log_warn "Configuration file already exists, backing up to server.conf.backup"
        cp "$CONFIG_DIR/server.conf" "$CONFIG_DIR/server.conf.backup.$(date +%s)"
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
    log_info "Configuring system networking..."

    # Enable IP forwarding
    log_info "Enabling IP forwarding..."
    sysctl -w net.ipv4.ip_forward=1 > /dev/null

    # Make it permanent
    if ! grep -q "net.ipv4.ip_forward.*=.*1" /etc/sysctl.conf 2>/dev/null; then
        echo "net.ipv4.ip_forward = 1" >> /etc/sysctl.conf
    fi

    log_success "IP forwarding enabled"

    # Configure NAT/MASQUERADE
    log_info "Configuring NAT (MASQUERADE)..."

    # Check if rule already exists
    if ! iptables -t nat -C POSTROUTING -s 10.8.0.0/24 -o "$EXTERNAL_INTERFACE" -j MASQUERADE 2>/dev/null; then
        iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$EXTERNAL_INTERFACE" -j MASQUERADE
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
    log_info "Configuring firewall..."

    # Detect and configure firewall
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
        log_info "Detected UFW firewall"
        ufw allow 4433/udp
        log_success "UFW: Allowed UDP port 4433"
    elif command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld; then
        log_info "Detected firewalld"
        firewall-cmd --permanent --add-port=4433/udp
        firewall-cmd --reload
        log_success "firewalld: Allowed UDP port 4433"
    else
        log_info "Configuring iptables directly..."
        if ! iptables -C INPUT -p udp --dport 4433 -j ACCEPT 2>/dev/null; then
            iptables -A INPUT -p udp --dport 4433 -j ACCEPT
            log_success "iptables: Allowed UDP port 4433"
        else
            log_warn "Firewall rule already exists"
        fi
    fi
}

# Create systemd service
create_systemd_service() {
    log_info "Creating systemd service..."

    cat > /etc/systemd/system/veil-server.service <<'EOF'
[Unit]
Description=VEIL VPN Server
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/veil-server --config /etc/veil/server.conf
Restart=on-failure
RestartSec=5
User=root
Group=root

# Security hardening
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/run /var/log
NoNewPrivileges=true

# Resource limits
LimitNOFILE=65536
LimitNPROC=512

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    log_success "Systemd service created"
}

# Start and enable service
start_service() {
    log_info "Starting VEIL server service..."

    systemctl enable veil-server
    systemctl start veil-server

    # Wait a moment for service to start
    sleep 2

    if systemctl is-active --quiet veil-server; then
        log_success "VEIL server is running!"
    else
        log_error "Failed to start VEIL server"
        log_error "Check logs with: sudo journalctl -u veil-server -n 50"
        exit 1
    fi
}

# Display summary and next steps
display_summary() {
    local server_ip
    server_ip=$(curl -s ifconfig.me 2>/dev/null || echo "<YOUR_SERVER_IP>")

    echo ""
    echo -e "${GREEN}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║                VEIL Server Installation Complete               ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    log_success "Server is running and ready for client connections"
    echo ""
    echo -e "${BLUE}Server Information:${NC}"
    echo "  • Server Address: $server_ip"
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
    echo "To connect clients, you need to securely transfer these files:"
    echo "  1. $CONFIG_DIR/server.key (rename to client.key on client)"
    echo "  2. $CONFIG_DIR/obfuscation.seed"
    echo ""
    echo "Example secure transfer command:"
    echo "  scp $CONFIG_DIR/server.key user@client:/tmp/client.key"
    echo "  scp $CONFIG_DIR/obfuscation.seed user@client:/tmp/"
    echo ""
    echo -e "${YELLOW}⚠ NEVER send these keys over email or insecure channels!${NC}"
    echo ""
    echo -e "${BLUE}Management Commands:${NC}"
    echo "  • Check status:  sudo systemctl status veil-server"
    echo "  • View logs:     sudo journalctl -u veil-server -f"
    echo "  • Restart:       sudo systemctl restart veil-server"
    echo "  • Stop:          sudo systemctl stop veil-server"
    echo ""
    echo -e "${BLUE}Network Status:${NC}"
    echo "  • IP Forwarding: $(sysctl -n net.ipv4.ip_forward)"
    echo "  • External Interface: $EXTERNAL_INTERFACE"
    echo ""
    echo -e "${GREEN}Installation completed successfully!${NC}"
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
    echo ""
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║            VEIL Server Automated Installer v1.0                ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Set trap for cleanup
    trap cleanup EXIT

    # Run installation steps
    check_root
    detect_os
    install_dependencies
    build_veil
    detect_external_interface
    generate_keys
    create_config
    configure_networking
    configure_firewall
    create_systemd_service
    start_service
    display_summary

    log_success "Installation completed successfully!"
}

# Run main function
main "$@"
