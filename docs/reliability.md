# VEIL Reliability Guide

This document describes the reliability and protection features implemented in Stage 6 of VEIL development.

## Overview

VEIL provides comprehensive reliability mechanisms to ensure stable operation under various conditions:

- **Advanced Rate Limiting**: Per-client bandwidth and packet rate limits with burst support
- **Session Lifecycle Management**: Structured state machine for session handling
- **Enhanced Idle Timeout**: Multi-level timeouts with keep-alive probing
- **Constrained Logging**: Rate-limited, sampled, async logging for production
- **Metrics System**: Low-overhead metrics collection with aggregation
- **Graceful Degradation**: Automatic adaptation under system overload
- **Session Migration**: Seamless client IP changes without reconnection

## Session Lifecycle

### Session States

Sessions transition through the following states:

```
                    +--------+
                    | Active |
                    +----+---+
                         |
           +-------------+-------------+
           |                           |
           v                           v
      +----------+              +------------+
      | Draining |              |  Expired   |
      +----+-----+              +------+-----+
           |                           |
           +-------------+-------------+
                         |
                         v
                  +------------+
                  | Terminated |
                  +------------+
```

- **Active**: Normal operation, accepting data
- **Draining**: Graceful shutdown in progress, processing pending packets
- **Expired**: Timeout reached, awaiting cleanup
- **Terminated**: Forcefully terminated

### Timeouts

Configure session timeouts in `veil-server.conf`:

```ini
[sessions]
# Idle timeout before disconnect
session_timeout = 300

# Warning notification before idle timeout
idle_warning_sec = 270

# Maximum session lifetime (regardless of activity)
absolute_timeout_sec = 86400

# Time allowed for graceful drain
drain_timeout_sec = 5
```

### Graceful Shutdown

When the server receives a shutdown signal:

1. All active sessions transition to `draining` state
2. Pending packets are processed (up to drain timeout)
3. Sessions then transition to `expired`
4. Resources are released

## Rate Limiting

### Per-Client Limits

Each client has independent rate limits:

```ini
[rate_limiting]
# Bandwidth limit per client
per_client_bandwidth_mbps = 100

# Packets per second limit
per_client_pps = 10000

# Burst allowance (1.5 = 50% burst capacity)
burst_allowance_factor = 1.5
```

### Burst Handling

The rate limiter uses a token bucket algorithm with burst support:

1. Tokens accumulate at the configured rate
2. Burst capacity = rate × burst_factor
3. When burst is exhausted, a penalty period applies
4. Critical traffic bypasses rate limiting

### Anti-Abuse Protection

Detect and mitigate abusive reconnection patterns:

```ini
[rate_limiting]
# Maximum reconnects per minute
reconnect_limit_per_minute = 5
```

### Traffic Priority

Traffic can be classified by priority:

- **Critical**: Session keepalives, control messages (never dropped)
- **High**: Important application data
- **Normal**: Regular traffic (default)
- **Low**: Background traffic (dropped first under pressure)

## Graceful Degradation

### Degradation Levels

| Level    | Actions                                           |
|----------|--------------------------------------------------|
| Normal   | Full operation                                    |
| Light    | Increased heartbeat interval, batch ACKs          |
| Moderate | Drop low-priority traffic, reduced retransmits    |
| Severe   | Reject new connections, minimal operations        |
| Critical | Emergency mode, hard limits on concurrent ops     |

### Configuration

```ini
[degradation]
# CPU threshold for degradation
cpu_threshold_percent = 80

# Memory threshold
memory_threshold_percent = 85

# Enable automatic degradation
enable_graceful_degradation = true

# Delay before escalating
escalation_delay_sec = 5

# Delay before recovering
recovery_delay_sec = 10
```

### Automatic Recovery

When load decreases below thresholds (minus hysteresis), the system automatically recovers to normal operation.

## Session Migration

Session migration allows clients to change IP addresses without losing their session.

### How It Works

1. Client requests a migration token before IP change
2. Token is valid for configured TTL
3. After IP change, client sends MIGRATE frame with token
4. Server validates token and updates session endpoint
5. Session state (replay window, retransmit buffer) is preserved

### Configuration

```ini
[migration]
enable_session_migration = true
migration_token_ttl_sec = 300
max_migrations_per_session = 5
migration_cooldown_sec = 10
```

### Use Cases

- Mobile clients switching networks (WiFi → cellular)
- NAT rebinding after router restart
- VPN failover scenarios

## Constrained Logging

### Rate Limiting

Prevent log flooding in production:

```ini
[logging]
# Max entries per second
rate_limit_logs_per_sec = 100
```

### Sampling

Reduce routine event logging overhead:

```ini
[logging]
# Sample 1% of routine events
sampling_rate = 0.01
```

### Async Logging

Non-blocking logging for hot paths:

```ini
[logging]
async_logging = true
```

### Structured Logging

JSON format for log aggregation systems:

```ini
[logging]
format = json
```

## Metrics

VEIL collects metrics for monitoring:

### Counter Metrics
- `packets_sent` / `packets_received`
- `bytes_sent` / `bytes_received`
- `sessions_created` / `sessions_expired`
- `rate_limit_violations`

### Gauge Metrics
- `active_sessions`
- `degradation_level`
- `memory_usage`

### Histogram Metrics
- `packet_latency`
- `retransmit_count`

### Export Formats

Metrics can be exported in:
- JSON format
- Prometheus format

## Best Practices

### Production Configuration

```ini
[sessions]
session_timeout = 300
idle_warning_sec = 270
absolute_timeout_sec = 86400

[rate_limiting]
per_client_bandwidth_mbps = 100
per_client_pps = 10000
burst_allowance_factor = 1.5
reconnect_limit_per_minute = 5

[degradation]
enable_graceful_degradation = true
cpu_threshold_percent = 80

[logging]
level = info
rate_limit_logs_per_sec = 100
sampling_rate = 0.01
async_logging = true
```

### High-Load Scenarios

For servers expecting 100+ concurrent clients:

1. Enable graceful degradation
2. Set conservative rate limits
3. Use async logging
4. Enable session migration for mobile clients
5. Configure appropriate memory limits per session

### Troubleshooting

**Sessions disconnecting unexpectedly:**
- Check `idle_timeout` configuration
- Verify keep-alive probes are working
- Check for rate limit violations in logs

**High CPU usage:**
- Enable graceful degradation
- Reduce logging verbosity
- Check for rate limit bypass issues

**Memory growth:**
- Set `max_memory_per_session_mb`
- Monitor retransmit buffer sizes
- Enable session cleanup

**Client IP changes cause disconnects:**
- Enable session migration
- Verify migration token TTL is sufficient
- Check migration cooldown settings
