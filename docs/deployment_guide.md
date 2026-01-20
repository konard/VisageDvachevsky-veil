# VEIL Deployment Guide

## Table of Contents
- [Introduction](#introduction)
- [Server Deployment](#server-deployment)
- [Client Deployment](#client-deployment)
- [Security Checklist](#security-checklist)
- [Performance Tuning](#performance-tuning)
- [Monitoring and Diagnostics](#monitoring-and-diagnostics)
- [Troubleshooting](#troubleshooting)

---

## Introduction

This guide covers production deployment of VEIL VPN servers and clients. For architecture details, see [Architecture Overview](architecture_overview.md). For configuration reference, see [Configuration](configuration.md).

### Prerequisites

**Server Requirements:**
- Linux server (Ubuntu 20.04+, Debian 11+, CentOS 8+)
- Kernel 4.9+ (for modern networking features)
- Public IP address
- UDP port access (default: 4433)
- Root/sudo access (for TUN device and firewall)

**Client Requirements:**
- Linux workstation/laptop (same distros as server)
- Kernel 4.9+
- Root/sudo access (for TUN device and routing)

**Build Dependencies:**
```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y \
  build-essential \
  cmake \
  libsodium-dev \
  pkg-config \
  git

# For GUI support (optional):
sudo apt-get install -y qt6-base-dev

# CentOS/RHEL
sudo yum install -y \
  gcc-c++ \
  cmake \
  libsodium-devel \
  pkgconfig \
  git

# For GUI support (optional):
sudo yum install -y qt6-qtbase-devel
```

**Note:** The GUI applications (`veil-gui-client` and `veil-gui-server`) are optional. If Qt6 is not installed, only the command-line versions (`veil-client` and `veil-server`) will be built. The CLI versions provide the same functionality through command-line arguments and configuration files.

---

## Server Deployment

### 1. Building the Server

```bash
# Clone repository
git clone https://github.com/VisageDvachevsky/VEIL.git
cd VEIL

# Create build directory
mkdir build && cd build

# Configure build
cmake .. -DCMAKE_BUILD_TYPE=Release

# Build (use -j$(nproc) for parallel build)
make -j$(nproc)

# Install binaries (optional)
sudo make install
# Installs to:
#   /usr/local/bin/veil-server
#   /usr/local/bin/veil-client
```

### 2. Initial Configuration

**Create configuration directory:**
```bash
sudo mkdir -p /etc/veil
sudo chmod 700 /etc/veil
```

**Generate cryptographic keys:**
```bash
# Pre-shared key (32 bytes)
sudo head -c 32 /dev/urandom > /etc/veil/server.key
sudo chmod 600 /etc/veil/server.key

# Obfuscation seed (32 bytes)
sudo head -c 32 /dev/urandom > /etc/veil/obfuscation.seed
sudo chmod 600 /etc/veil/obfuscation.seed
```

**Create server configuration:**
```bash
sudo cp configs/veil-server.conf.example /etc/veil/server.conf
sudo chmod 600 /etc/veil/server.conf
```

**Edit `/etc/veil/server.conf`:**
```ini
[server]
listen_address = 0.0.0.0
listen_port = 4433
verbose = false

[tun]
device_name = veil0
ip_address = 10.8.0.1
netmask = 255.255.255.0
mtu = 1400

[crypto]
preshared_key_file = /etc/veil/server.key

[obfuscation]
profile_seed_file = /etc/veil/obfuscation.seed

[nat]
external_interface = eth0  # ← Change to your internet-facing interface
enable_forwarding = true
use_masquerade = true

[sessions]
max_clients = 256
session_timeout = 300

[ip_pool]
start = 10.8.0.2
end = 10.8.0.254
```

### 3. Firewall Configuration

**Allow UDP traffic:**
```bash
# UFW (Ubuntu/Debian)
sudo ufw allow 4433/udp
sudo ufw reload

# firewalld (CentOS/RHEL)
sudo firewall-cmd --permanent --add-port=4433/udp
sudo firewall-cmd --reload

# iptables (manual)
sudo iptables -A INPUT -p udp --dport 4433 -j ACCEPT
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

**Enable IP forwarding:**
```bash
# Temporary (until reboot)
sudo sysctl -w net.ipv4.ip_forward=1

# Permanent
echo "net.ipv4.ip_forward = 1" | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

**Configure NAT (if not using veil-server's built-in NAT):**
```bash
# Find your external interface
ip route | grep default
# Example output: default via 192.168.1.1 dev eth0

# Enable MASQUERADE
sudo iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE
sudo iptables-save | sudo tee /etc/iptables/rules.v4
```

### 4. Testing the Server (Manual Mode)

**Run server in foreground (for testing):**
```bash
sudo /usr/local/bin/veil-server --config /etc/veil/server.conf --verbose
```

**Expected output:**
```
[INFO] VEIL Server starting...
[INFO] Loaded PSK from /etc/veil/server.key
[INFO] Loaded obfuscation seed from /etc/veil/obfuscation.seed
[INFO] Opened TUN device: veil0 (10.8.0.1/24)
[INFO] Configured NAT: eth0 → 10.8.0.0/24
[INFO] Listening on 0.0.0.0:4433 (UDP)
[INFO] Server ready, waiting for clients...
```

**Verify TUN device:**
```bash
ip addr show veil0
# Should show:
# veil0: <POINTOPOINT,UP,LOWER_UP> mtu 1400
#     inet 10.8.0.1/24 scope global veil0
```

**Verify NAT:**
```bash
sudo iptables -t nat -L -v -n | grep 10.8.0.0
# Should show MASQUERADE rule
```

### 5. Systemd Service Setup

**Create service file:**
```bash
sudo tee /etc/systemd/system/veil-server.service > /dev/null <<'EOF'
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
ReadWritePaths=/var/run
NoNewPrivileges=true

# Resource limits
LimitNOFILE=65536
LimitNPROC=512

[Install]
WantedBy=multi-user.target
EOF
```

**Enable and start service:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable veil-server
sudo systemctl start veil-server
sudo systemctl status veil-server
```

**View logs:**
```bash
# Realtime logs
sudo journalctl -u veil-server -f

# Recent logs
sudo journalctl -u veil-server -n 100

# Logs since boot
sudo journalctl -u veil-server -b
```

### 6. Distributing Keys to Clients

**Securely transfer keys:**
```bash
# On server:
cd /etc/veil
tar czf veil-client-keys.tar.gz server.key obfuscation.seed

# Transfer via SCP (example):
scp /etc/veil/veil-client-keys.tar.gz user@client-machine:/tmp/

# On client:
cd /tmp
tar xzf veil-client-keys.tar.gz
sudo mkdir -p /etc/veil
sudo mv server.key /etc/veil/client.key
sudo mv obfuscation.seed /etc/veil/
sudo chmod 600 /etc/veil/client.key /etc/veil/obfuscation.seed
rm veil-client-keys.tar.gz

# Clean up server tarball
rm /etc/veil/veil-client-keys.tar.gz
```

**Security notes:**
- Use secure channels (SCP, SFTP, or physical media)
- Delete tarball after transfer
- Never send keys via email or insecure messaging

---

## Client Deployment

### 1. Building the Client

```bash
# Same as server build
git clone https://github.com/VisageDvachevsky/VEIL.git
cd VEIL
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
sudo make install
```

### 2. Client Configuration

**Create configuration:**
```bash
sudo mkdir -p /etc/veil
sudo cp configs/veil-client.conf.example /etc/veil/client.conf
sudo chmod 600 /etc/veil/client.conf
```

**Edit `/etc/veil/client.conf`:**
```ini
[client]
server_address = vpn.example.com  # ← Change to your server's IP or hostname
server_port = 4433

[tun]
device_name = veil0
ip_address = 10.8.0.2  # Will be assigned by server, placeholder
netmask = 255.255.255.0
mtu = 1400

[crypto]
preshared_key_file = /etc/veil/client.key

[obfuscation]
profile_seed_file = /etc/veil/obfuscation.seed

[routing]
default_route = true  # Route all traffic through VPN

[connection]
auto_reconnect = true
reconnect_interval_ms = 5000
```

### 3. Testing the Client

**Run client in foreground:**
```bash
sudo /usr/local/bin/veil-client --config /etc/veil/client.conf --verbose
```

**Expected output:**
```
[INFO] VEIL Client starting...
[INFO] Loaded PSK from /etc/veil/client.key
[INFO] Loaded obfuscation seed from /etc/veil/obfuscation.seed
[INFO] Connecting to vpn.example.com:4433...
[INFO] Sending handshake INIT...
[INFO] Received handshake RESPONSE
[INFO] Handshake successful, session_id=0x123456789abcdef0
[INFO] Opened TUN device: veil0 (10.8.0.5/24)
[INFO] Configured routing: default via 10.8.0.1
[INFO] Client connected and ready
```

**Verify connection:**
```bash
# Check TUN device
ip addr show veil0

# Check routing
ip route show

# Test connectivity through tunnel
ping -c 3 10.8.0.1  # Server tunnel IP
ping -c 3 8.8.8.8   # Public internet (if default_route=true)

# Check public IP (should show server's IP if routing all traffic)
curl ifconfig.me
```

### 4. Client Systemd Service

**Create service file:**
```bash
sudo tee /etc/systemd/system/veil-client.service > /dev/null <<'EOF'
[Unit]
Description=VEIL VPN Client
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/veil-client --config /etc/veil/client.conf
Restart=on-failure
RestartSec=5
User=root
Group=root

# Security hardening
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/run
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
```

**Enable and start:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable veil-client
sudo systemctl start veil-client
sudo systemctl status veil-client
```

### 5. Verifying End-to-End Connectivity

**From client, test tunnel:**
```bash
# Ping server tunnel IP
ping -c 3 10.8.0.1

# Traceroute through tunnel
traceroute 8.8.8.8

# DNS resolution through tunnel
dig google.com

# Check public IP
curl https://ifconfig.me
# Should show server's public IP if routing all traffic
```

**From server, check connected clients:**
```bash
# View logs for client connections
sudo journalctl -u veil-server | grep "session established"

# Check active TUN interface traffic
sudo iftop -i veil0

# View routing table
ip route show table all | grep veil0
```

---

## Security Checklist

### Pre-Production Checklist

- [ ] **PSK Security**
  - [ ] Generated with cryptographically secure RNG (`/dev/urandom`)
  - [ ] File permissions: 600 (owner read/write only)
  - [ ] Never transmitted over insecure channels
  - [ ] Unique per deployment (don't reuse default/example keys)

- [ ] **Obfuscation Seed Security**
  - [ ] Generated independently from PSK
  - [ ] File permissions: 600
  - [ ] Same seed on client and server
  - [ ] Rotated periodically (recommended: every 90 days)

- [ ] **Firewall Configuration**
  - [ ] UDP port open only for VPN (4433)
  - [ ] SSH access protected (port 22, key-only auth)
  - [ ] All other inbound ports closed
  - [ ] Rate limiting enabled (prevent DoS)

- [ ] **Server Hardening**
  - [ ] Non-root user for service (if possible, via capabilities)
  - [ ] SELinux/AppArmor enabled
  - [ ] Automatic security updates enabled
  - [ ] Minimal packages installed (attack surface reduction)
  - [ ] SSH key-only authentication (disable password auth)

- [ ] **Network Security**
  - [ ] IP forwarding enabled only on server
  - [ ] NAT configured correctly (no accidental routing loops)
  - [ ] Split-tunnel vs full-tunnel decision documented
  - [ ] DNS leak prevention (client routes DNS through VPN)

- [ ] **Logging and Monitoring**
  - [ ] Centralized log aggregation (syslog, journald)
  - [ ] Log rotation configured
  - [ ] Alerts for connection failures, DoS attempts
  - [ ] Regular log review process

### Production Security Best Practices

**1. Key Rotation Policy**

Rotate PSK and obfuscation seed quarterly:

```bash
# Generate new keys
sudo head -c 32 /dev/urandom > /etc/veil/server.key.new
sudo head -c 32 /dev/urandom > /etc/veil/obfuscation.seed.new

# Distribute to clients (secure channel)
# ...

# After all clients updated:
sudo mv /etc/veil/server.key.new /etc/veil/server.key
sudo mv /etc/veil/obfuscation.seed.new /etc/veil/obfuscation.seed

# Restart services
sudo systemctl restart veil-server
```

**2. Silent Drop Mode**

Ensure server runs with silent drop (anti-probing):
- Invalid handshakes → no response
- Replay attacks → no response
- Wrong PSK → no response

This is default behavior; verify in logs:
```bash
sudo journalctl -u veil-server | grep -i "silent drop"
# Should show dropped invalid packets
```

**3. Rate Limiting**

Enable per-client rate limiting in `/etc/veil/server.conf`:
```ini
[rate_limiting]
per_client_bandwidth_mbps = 100
per_client_pps = 10000
burst_allowance_factor = 1.5
reconnect_limit_per_minute = 5
```

**4. Session Timeouts**

Configure aggressive timeouts to prevent stale sessions:
```ini
[sessions]
session_timeout = 300          # 5 minutes idle
idle_warning_sec = 270         # Warn at 4.5 minutes
absolute_timeout_sec = 86400   # Max 24 hours
```

**5. Resource Limits**

Prevent resource exhaustion:
```ini
[sessions]
max_clients = 256
max_memory_per_session_mb = 10

[degradation]
enable_graceful_degradation = true
cpu_threshold_percent = 80
memory_threshold_percent = 85
```

---

## Performance Tuning

### System-Level Tuning

**UDP Buffer Sizes:**
```bash
# Increase UDP receive buffer (recommended: 16MB)
sudo sysctl -w net.core.rmem_max=16777216
sudo sysctl -w net.core.rmem_default=16777216

# Increase UDP send buffer
sudo sysctl -w net.core.wmem_max=16777216
sudo sysctl -w net.core.wmem_default=16777216

# Make permanent
cat <<EOF | sudo tee -a /etc/sysctl.conf
net.core.rmem_max = 16777216
net.core.rmem_default = 16777216
net.core.wmem_max = 16777216
net.core.wmem_default = 16777216
EOF
```

**Network Stack Tuning:**
```bash
# TCP congestion control (BBR for better performance)
sudo sysctl -w net.core.default_qdisc=fq
sudo sysctl -w net.ipv4.tcp_congestion_control=bbr

# Increase connection tracking size
sudo sysctl -w net.netfilter.nf_conntrack_max=262144

# Make permanent
cat <<EOF | sudo tee -a /etc/sysctl.conf
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.netfilter.nf_conntrack_max = 262144
EOF

sudo sysctl -p
```

**File Descriptor Limits:**
```bash
# Increase for high-concurrency servers
ulimit -n 65536

# Make permanent (add to /etc/security/limits.conf)
cat <<EOF | sudo tee -a /etc/security/limits.conf
*  soft  nofile  65536
*  hard  nofile  65536
EOF
```

### Application-Level Tuning

**MTU Optimization:**

Find optimal MTU:
```bash
# Test MTU from client to server
ping -M do -s 1472 vpn.example.com  # 1500 - 28 (IP+UDP headers)

# If successful, try 1472
# If "Frag needed", reduce: 1400, 1300, etc.

# Once found, update config:
sudo vim /etc/veil/server.conf
# [tun]
# mtu = 1400  ← Set to tested value
```

**Worker Threads (if multithreading enabled):**
```bash
# In future versions with threading:
# [server]
# worker_threads = 4  # Set to number of CPU cores
```

---

## Monitoring and Diagnostics

### Server Monitoring

**Connection Stats:**
```bash
# View active sessions
sudo veil-server --status  # (If implemented)

# Or parse logs:
sudo journalctl -u veil-server --since "10 minutes ago" | grep "session established"
```

**Network Statistics:**
```bash
# TUN device statistics
ip -s link show veil0

# Detailed interface stats
sudo ifconfig veil0

# Monitor traffic in real-time
sudo iftop -i veil0
sudo nethogs veil0
```

**System Resource Usage:**
```bash
# CPU and memory usage
top -p $(pgrep veil-server)

# Detailed process info
ps aux | grep veil-server

# Open file descriptors
sudo lsof -p $(pgrep veil-server) | wc -l
```

**Log Analysis:**
```bash
# Handshake failures
sudo journalctl -u veil-server | grep "handshake failed"

# Replay attack attempts
sudo journalctl -u veil-server | grep "replay detected"

# Session timeouts
sudo journalctl -u veil-server | grep "session timeout"

# Error summary
sudo journalctl -u veil-server -p err -n 50
```

### Client Diagnostics

**Connection Status:**
```bash
# Check if client is connected
systemctl status veil-client

# View handshake logs
sudo journalctl -u veil-client | grep "handshake"

# Check session ID
sudo journalctl -u veil-client | grep "session_id"
```

**Tunnel Verification:**
```bash
# Verify TUN device is up
ip link show veil0

# Check routing
ip route show | grep veil0

# Test connectivity
ping -c 3 10.8.0.1  # Server tunnel IP
ping -c 3 8.8.8.8   # Public internet
```

**Throughput Testing:**
```bash
# Install iperf3 on both server and client
sudo apt-get install iperf3

# On server:
iperf3 -s -B 10.8.0.1

# On client:
iperf3 -c 10.8.0.1 -t 30  # 30-second test

# Expected: 50-500 Mbps depending on hardware and network
```

**Latency Testing:**
```bash
# RTT measurement
ping -c 100 10.8.0.1 | tail -1
# Should show avg RTT ~10-50ms for most deployments

# MTR (better than traceroute)
mtr 10.8.0.1 -c 100 -r
```

---

## Troubleshooting

### Common Issues

#### 1. Handshake Fails

**Symptom:**
```
[ERROR] Handshake failed: HMAC verification failed
```

**Causes:**
- PSK mismatch between client and server
- Corrupted key file
- Time skew between client and server (>30s)

**Solutions:**
```bash
# Verify PSK files match
md5sum /etc/veil/server.key  # On server
md5sum /etc/veil/client.key  # On client
# Should be identical

# Check system time
date -u  # On both client and server
# If skewed >30s, sync clocks:
sudo ntpdate pool.ntp.org
# Or enable NTP:
sudo systemctl enable systemd-timesyncd
sudo systemctl start systemd-timesyncd

# Regenerate keys if corrupted
sudo head -c 32 /dev/urandom > /etc/veil/server.key
# Copy to client and restart both
```

#### 2. No Network Connectivity Through Tunnel

**Symptom:**
```
Tunnel established, but no internet access
```

**Causes:**
- NAT not configured
- IP forwarding disabled
- Firewall blocking forwarded traffic

**Solutions:**
```bash
# Check IP forwarding (server)
sysctl net.ipv4.ip_forward
# Should be: net.ipv4.ip_forward = 1

# Check NAT rules (server)
sudo iptables -t nat -L -v -n | grep MASQUERADE
# Should show MASQUERADE rule for 10.8.0.0/24

# Check routing (client)
ip route show
# Should show: default via 10.8.0.1 dev veil0

# Test routing from client
traceroute -n 8.8.8.8
# First hop should be 10.8.0.1
```

#### 3. High Latency / Packet Loss

**Symptom:**
```
ping RTT >200ms or packet loss >5%
```

**Causes:**
- Server overloaded
- Network congestion
- MTU misconfiguration

**Solutions:**
```bash
# Check server load
top  # Look for high CPU/memory usage

# Check MTU
ping -M do -s 1400 -c 10 10.8.0.1  # From client
# If fails, reduce MTU in config

# Check packet loss
mtr 10.8.0.1 -c 100 -r
# Look for loss% column

# Enable verbose logging to see retransmissions
sudo vim /etc/veil/server.conf
# Set: verbose = true
sudo systemctl restart veil-server
```

#### 4. Client Cannot Resolve DNS

**Symptom:**
```
ping 8.8.8.8 works, but ping google.com fails
```

**Causes:**
- DNS not routed through VPN
- /etc/resolv.conf not updated

**Solutions:**
```bash
# Check DNS routing
dig google.com
# Should query through tunnel

# Manually set DNS (temporary)
echo "nameserver 8.8.8.8" | sudo tee /etc/resolv.conf

# Permanent DNS (using systemd-resolved)
sudo vim /etc/systemd/resolved.conf
# Add: DNS=8.8.8.8
sudo systemctl restart systemd-resolved

# Or use resolvconf
echo "nameserver 8.8.8.8" | sudo resolvconf -a veil0
```

#### 5. Server Unresponsive / High Load

**Symptom:**
```
Server CPU 100%, clients cannot connect
```

**Causes:**
- DoS attack (handshake flood)
- Memory leak
- Too many stale sessions

**Solutions:**
```bash
# Check for DoS (many failed handshakes)
sudo journalctl -u veil-server | grep "rate limit" | wc -l

# Enable stricter rate limiting
sudo vim /etc/veil/server.conf
# [rate_limiting]
# reconnect_limit_per_minute = 3
sudo systemctl restart veil-server

# Clean up stale sessions
sudo journalctl -u veil-server | grep "cleanup expired"

# Check memory usage
ps aux | grep veil-server
# If RSS is growing unbounded, possible leak (report bug)

# Restart service
sudo systemctl restart veil-server
```

#### 6. Systemd Service Fails to Start

**Symptom:**
```
systemctl status veil-server
Active: failed (Result: exit-code)
```

**Causes:**
- Missing configuration file
- Permission denied on TUN device
- Port already in use

**Solutions:**
```bash
# Check detailed error
sudo journalctl -u veil-server -n 50

# Verify config file exists
ls -l /etc/veil/server.conf

# Check TUN device permissions (needs root or CAP_NET_ADMIN)
sudo systemctl edit veil-server
# Add:
# [Service]
# AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE

# Check if port in use
sudo ss -ulnp | grep 4433
# If in use, kill process or change port

# Test manually
sudo /usr/local/bin/veil-server --config /etc/veil/server.conf --verbose
# See direct error output
```

### Debug Mode

**Enable verbose logging:**
```bash
# Temporary (command line)
sudo veil-server --config /etc/veil/server.conf --verbose

# Permanent (config file)
sudo vim /etc/veil/server.conf
# [server]
# verbose = true

sudo systemctl restart veil-server
```

**Increase log verbosity (if built with debug support):**
```bash
# Rebuild with debug symbols
cmake .. -DCMAKE_BUILD_TYPE=Debug -DENABLE_TRACE_LOGGING=ON
make -j$(nproc)
sudo make install
```

**Capture packet dump:**
```bash
# Server side
sudo tcpdump -i eth0 udp port 4433 -w /tmp/veil-server-dump.pcap

# Client side
sudo tcpdump -i any udp port 4433 -w /tmp/veil-client-dump.pcap

# Analyze with Wireshark
wireshark /tmp/veil-server-dump.pcap
```

### Getting Help

**Before reporting issues:**
1. Check logs: `sudo journalctl -u veil-server -n 200`
2. Verify configuration: `cat /etc/veil/server.conf`
3. Test basic connectivity: `ping <server_ip>`
4. Check firewall: `sudo iptables -L -v -n`

**Reporting bugs:**
- Include VEIL version: `veil-server --version`
- Include OS/kernel: `uname -a`
- Include relevant logs (sanitize IPs/keys)
- Describe expected vs actual behavior

---

## Example Production Deployment

### Scenario: Small VPN Server (10-50 clients)

**Server Specs:**
- Cloud VM: 2 vCPUs, 4GB RAM
- OS: Ubuntu 22.04 LTS
- Network: 1 Gbps uplink
- Public IP: 203.0.113.42

**Configuration:**
```ini
[server]
listen_address = 0.0.0.0
listen_port = 4433

[sessions]
max_clients = 50
session_timeout = 600
cleanup_interval = 60

[rate_limiting]
per_client_bandwidth_mbps = 100
reconnect_limit_per_minute = 5

[degradation]
enable_graceful_degradation = true
cpu_threshold_percent = 70
```

**Expected Performance:**
- Throughput: ~500 Mbps aggregate
- Latency: +5-10ms overhead
- Max clients: 50 concurrent

**Monitoring:**
```bash
# CPU usage should be <30% under normal load
# Memory usage ~500MB + (10MB × num_clients)
# Network throughput: monitor with iftop
```

---

**End of Deployment Guide**
