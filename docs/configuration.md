# VEIL Configuration Reference

This document provides a complete reference for all VEIL server configuration options.

## Configuration File Location

Default location: `/etc/veil/server.conf`

Override with command line: `veil-server --config /path/to/config.conf`

## Configuration Sections

### [server]

Basic server settings.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `listen_address` | string | `0.0.0.0` | IP address to listen on |
| `listen_port` | int | `4433` | UDP port for client connections |
| `daemon` | bool | `false` | Run as background daemon |
| `verbose` | bool | `false` | Enable verbose logging |

### [tun]

TUN device configuration.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `device_name` | string | `veil0` | TUN interface name |
| `ip_address` | string | `10.8.0.1` | Server tunnel IP address |
| `netmask` | string | `255.255.255.0` | Tunnel network mask |
| `mtu` | int | `1400` | Maximum transmission unit |

### [crypto]

Cryptographic settings.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `preshared_key_file` | path | required | Path to 32-byte PSK file |

Generate PSK: `head -c 32 /dev/urandom > /etc/veil/server.key`

### [obfuscation]

Traffic obfuscation settings.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `profile_seed_file` | path | required | Path to 32-byte seed file |

Generate seed: `head -c 32 /dev/urandom > /etc/veil/obfuscation.seed`

### [nat]

Network Address Translation settings.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `external_interface` | string | `eth0` | Internet-facing interface |
| `enable_forwarding` | bool | `true` | Enable IP forwarding |
| `use_masquerade` | bool | `true` | Use MASQUERADE (vs SNAT) |
| `snat_source` | string | - | Source IP for SNAT mode |

### [sessions]

Session management settings.

| Parameter | Type | Default | Range | Description |
|-----------|------|---------|-------|-------------|
| `max_clients` | int | `256` | 1-65535 | Maximum concurrent clients |
| `session_timeout` | int | `300` | 60-86400 | Idle timeout (seconds) |
| `idle_warning_sec` | int | `270` | - | Warning before idle timeout |
| `absolute_timeout_sec` | int | `86400` | 3600-604800 | Max session lifetime |
| `max_memory_per_session_mb` | int | `10` | 1-1024 | Memory limit per session |
| `cleanup_interval` | int | `60` | 10-3600 | Cleanup check interval |
| `drain_timeout_sec` | int | `5` | 1-60 | Graceful drain timeout |

### [ip_pool]

Client IP address pool.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `start` | string | `10.8.0.2` | First IP in pool |
| `end` | string | `10.8.0.254` | Last IP in pool |

### [daemon]

Daemon mode settings.

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `pid_file` | path | `/var/run/veil-server.pid` | PID file location |
| `log_file` | path | - | Log file (empty = stdout) |
| `user` | string | - | Drop privileges to user |
| `group` | string | - | Drop privileges to group |

### [rate_limiting]

Per-client rate limiting. *(Stage 6)*

| Parameter | Type | Default | Range | Description |
|-----------|------|---------|-------|-------------|
| `per_client_bandwidth_mbps` | int | `100` | 1-10000 | Bandwidth limit (Mbps) |
| `per_client_pps` | int | `10000` | 100-1000000 | Packets per second limit |
| `burst_allowance_factor` | float | `1.5` | 1.0-5.0 | Burst capacity multiplier |
| `reconnect_limit_per_minute` | int | `5` | 1-60 | Anti-abuse reconnect limit |
| `enable_traffic_shaping` | bool | `true` | - | Enable priority queuing |

**Bandwidth Calculation:**
- Actual limit = `per_client_bandwidth_mbps` × 1,000,000 / 8 bytes/sec
- Burst capacity = limit × `burst_allowance_factor`

### [degradation]

Graceful degradation under load. *(Stage 6)*

| Parameter | Type | Default | Range | Description |
|-----------|------|---------|-------|-------------|
| `cpu_threshold_percent` | int | `80` | 50-99 | CPU % for degradation |
| `memory_threshold_percent` | int | `85` | 50-99 | Memory % for degradation |
| `enable_graceful_degradation` | bool | `true` | - | Enable auto-degradation |
| `escalation_delay_sec` | int | `5` | 1-60 | Delay before escalating |
| `recovery_delay_sec` | int | `10` | 5-300 | Delay before recovering |

**Degradation Levels:**
1. Normal (< thresholds)
2. Light (60-75% of threshold)
3. Moderate (75-85% of threshold)
4. Severe (85-95% of threshold)
5. Critical (> 95% of threshold)

### [logging]

Logging configuration. *(Stage 6)*

| Parameter | Type | Default | Options | Description |
|-----------|------|---------|---------|-------------|
| `level` | string | `info` | trace, debug, info, warn, error, critical | Minimum log level |
| `rate_limit_logs_per_sec` | int | `100` | 0-10000 | Max logs/sec (0=unlimited) |
| `sampling_rate` | float | `0.01` | 0.0-1.0 | Sampling rate for routine events |
| `async_logging` | bool | `true` | - | Non-blocking logging |
| `format` | string | `json` | text, json | Output format |

### [migration]

Session migration settings. *(Stage 6)*

| Parameter | Type | Default | Range | Description |
|-----------|------|---------|-------|-------------|
| `enable_session_migration` | bool | `true` | - | Enable IP change support |
| `migration_token_ttl_sec` | int | `300` | 60-3600 | Token validity period |
| `max_migrations_per_session` | int | `5` | 1-100 | Max migrations per session |
| `migration_cooldown_sec` | int | `10` | 1-300 | Minimum time between migrations |

## Example Configurations

### Minimal Configuration

```ini
[server]
listen_port = 4433

[tun]
device_name = veil0
ip_address = 10.8.0.1

[crypto]
preshared_key_file = /etc/veil/server.key

[obfuscation]
profile_seed_file = /etc/veil/obfuscation.seed

[nat]
external_interface = eth0
```

### Production Configuration

```ini
[server]
listen_address = 0.0.0.0
listen_port = 4433
daemon = true

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
external_interface = eth0
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
user = nobody
group = nogroup

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
```

### High-Security Configuration

```ini
[sessions]
max_clients = 100
session_timeout = 180
absolute_timeout_sec = 3600  # 1 hour max

[rate_limiting]
per_client_bandwidth_mbps = 50
per_client_pps = 5000
reconnect_limit_per_minute = 2

[migration]
enable_session_migration = false  # Disabled for security
```

### High-Throughput Configuration

```ini
[sessions]
max_clients = 1000
session_timeout = 600
max_memory_per_session_mb = 50

[rate_limiting]
per_client_bandwidth_mbps = 1000
per_client_pps = 100000
burst_allowance_factor = 2.0

[logging]
level = warn  # Reduce logging overhead
rate_limit_logs_per_sec = 10
sampling_rate = 0.001  # Minimal sampling
```

## Environment Variables

Configuration values can also be set via environment variables:

```bash
VEIL_LISTEN_PORT=4433
VEIL_MAX_CLIENTS=256
VEIL_LOG_LEVEL=info
```

Environment variables take precedence over configuration file values.
