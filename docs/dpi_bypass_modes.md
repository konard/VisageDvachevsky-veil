# DPI Bypass Modes for VEIL

## Overview

VEIL implements four distinct DPI (Deep Packet Inspection) bypass modes to evade various traffic analysis systems. Each mode simulates different traffic patterns to blend with legitimate network activity.

## Mode Profiles

### Mode A: IoT Mimic

**Purpose:** Simulate IoT device telemetry traffic (smart sensors, home automation)

**Traffic Characteristics:**
- **Packet Sizes:** Predominantly small (60-150 bytes), occasional medium bursts
- **Timing Pattern:** Regular heartbeats every 10-20 seconds
- **Payload Structure:** Sensor-like data (temperature, humidity, battery readings)
- **Burst Behavior:** Minimal bursts, mostly steady periodic traffic
- **Entropy:** Medium entropy (structured data with some randomness)

**Configuration:**
```cpp
ObfuscationProfile iot_mimic_mode{
  .enabled = true,
  .max_padding_size = 200,
  .min_padding_size = 20,
  .min_prefix_size = 4,
  .max_prefix_size = 8,
  .heartbeat_min = 10s,
  .heartbeat_max = 20s,
  .timing_jitter_enabled = true,
  .max_timing_jitter_ms = 30,
  .size_variance = 0.3f,  // Low variance for consistent sensor traffic
  .padding_distribution = {
    .small_weight = 70,   // Predominantly small packets
    .medium_weight = 25,
    .large_weight = 5,
    .small_min = 20,
    .small_max = 150,
    .medium_min = 150,
    .medium_max = 300,
    .large_min = 300,
    .large_max = 500,
    .jitter_range = 15
  },
  .use_advanced_padding = true,
  .timing_jitter_model = TimingJitterModel::kPoisson,
  .timing_jitter_scale = 0.8f,  // Lower jitter scale for predictable traffic
  .heartbeat_type = HeartbeatType::kIoTSensor,
  .heartbeat_timing_model = HeartbeatTimingModel::kExponential,  // Non-periodic timing
  .exponential_mean_seconds = 15.0f,
  .exponential_max_gap = 60s,
  .exponential_long_gap_probability = 0.15f,
  .heartbeat_entropy_normalization = true
};
```

**Special Features:**
- **Non-Periodic Heartbeats:** Uses exponential distribution to avoid regular timing patterns
- **Occasional Long Gaps:** 15% probability of gaps up to 60 seconds to defeat pattern detection
- **IoT Sensor Payloads:** Mimics temperature/humidity/battery telemetry data

**Use Case:** General purpose, good balance of stealth and performance.

---

### Mode B: QUIC-Like (with WebSocket Protocol Wrapper)

**Purpose:** Mimic WebSocket traffic with real protocol headers for enhanced DPI evasion

**Traffic Characteristics:**
- **Packet Sizes:** Large initial packets (ClientHello-like), then variable
- **Timing Pattern:** Bursty with varying inter-packet delays
- **Payload Structure:** High entropy throughout (encrypted frames)
- **Burst Behavior:** Initial burst, then sporadic activity with quiet periods
- **Entropy:** High entropy (looks like encrypted WebSocket binary frames)
- **Protocol Headers:** Real WebSocket binary frames (RFC 6455) - **NEW!**

**Configuration:**
```cpp
ObfuscationProfile quic_like_mode{
  .enabled = true,
  .max_padding_size = 1200,
  .min_padding_size = 100,
  .min_prefix_size = 8,
  .max_prefix_size = 16,
  .heartbeat_min = 30s,
  .heartbeat_max = 60s,
  .timing_jitter_enabled = true,
  .max_timing_jitter_ms = 100,
  .size_variance = 0.7f,  // High variance like QUIC
  .padding_distribution = {
    .small_weight = 20,
    .medium_weight = 30,
    .large_weight = 50,   // Predominantly large packets
    .small_min = 100,
    .small_max = 300,
    .medium_min = 300,
    .medium_max = 800,
    .large_min = 800,
    .large_max = 1200,
    .jitter_range = 50
  },
  .use_advanced_padding = true,
  .timing_jitter_model = TimingJitterModel::kExponential,  // Bursty timing
  .timing_jitter_scale = 1.5f,  // Higher jitter for QUIC-like burstiness
  .heartbeat_type = HeartbeatType::kRandomSize,  // Varied payload sizes
  .heartbeat_timing_model = HeartbeatTimingModel::kExponential,
  .exponential_mean_seconds = 45.0f,
  .exponential_max_gap = 180s,
  .exponential_long_gap_probability = 0.2f,
  .heartbeat_entropy_normalization = true,
  .protocol_wrapper = ProtocolWrapperType::kWebSocket,
  .is_client_to_server = true
};
```

**Special Features:**
- **WebSocket Protocol Wrapper:** Wraps VEIL packets in RFC 6455-compliant WebSocket binary frames
- **Masking:** Client-to-server frames use proper WebSocket masking
- **DPI Resistance:** DPI systems see legitimate WebSocket traffic, not just statistical mimicry
- **Random-Size Heartbeats:** Payload size varies (8-200 bytes) to prevent size-based detection
- **Exponential Timing:** Non-periodic heartbeats with 20% probability of long gaps (up to 3 minutes)
- First 3-5 packets should be large (>1000 bytes) to mimic initial handshake

**DPI Systems Evaded:**
- **Protocol Fingerprinting DPI:** WebSocket headers look legitimate to signature-based DPI
- **Statistical Analysis:** Combined with traffic shaping, provides multi-layer evasion
- **Simple Firewalls:** Appears as normal WebSocket traffic (commonly used for web apps)

**Use Case:** High-throughput scenarios, modern web traffic camouflage, evasion of protocol-aware DPI.

---

### Mode C: Random-Noise Stealth

**Purpose:** Maximum unpredictability and entropy

**Traffic Characteristics:**
- **Packet Sizes:** Completely random within full range
- **Timing Pattern:** Maximum jitter, unpredictable intervals
- **Payload Structure:** Maximum entropy (pure noise)
- **Burst Behavior:** Unpredictable, simulates poor Wi-Fi conditions
- **Entropy:** Maximum entropy

**Configuration:**
```cpp
ObfuscationProfile random_noise_mode{
  .enabled = true,
  .max_padding_size = 1000,
  .min_padding_size = 0,
  .min_prefix_size = 4,
  .max_prefix_size = 20,
  .heartbeat_min = 60s,     // Infrequent heartbeats
  .heartbeat_max = 180s,
  .timing_jitter_enabled = true,
  .max_timing_jitter_ms = 500,  // Extreme jitter
  .size_variance = 1.0f,  // Maximum variance
  .padding_distribution = {
    .small_weight = 33,   // Equal distribution
    .medium_weight = 33,
    .large_weight = 34,
    .small_min = 0,
    .small_max = 333,
    .medium_min = 333,
    .medium_max = 666,
    .large_min = 666,
    .large_max = 1000,
    .jitter_range = 100
  },
  .use_advanced_padding = true,
  .timing_jitter_model = TimingJitterModel::kUniform,  // Random timing
  .timing_jitter_scale = 2.0f,  // Maximum jitter scale
  .heartbeat_type = HeartbeatType::kRandomSize,  // Varied payload sizes
  .heartbeat_timing_model = HeartbeatTimingModel::kBurst,  // Burst mode
  .burst_heartbeat_count_min = 2,
  .burst_heartbeat_count_max = 4,
  .burst_silence_min = 90s,
  .burst_silence_max = 240s,
  .burst_interval = 500ms,
  .heartbeat_entropy_normalization = true
};
```

**Special Features:**
- **Burst Mode Heartbeats:** Sends 2-4 heartbeats rapidly (500ms apart), then silent for 90-240 seconds
- **Maximum Unpredictability:** Breaks all temporal correlation patterns
- Aggressive fragmentation (split messages more frequently)
- No regular patterns whatsoever
- Simulates packet loss recovery patterns

**Use Case:** Extreme censorship scenarios, when detection risk is high.

---

### Mode D: Trickle Mode

**Purpose:** Low-and-slow traffic for maximum stealth

**Traffic Characteristics:**
- **Packet Sizes:** Small only (mimics very constrained IoT)
- **Timing Pattern:** Very slow, high delays between packets
- **Payload Structure:** Minimal, structured like ultra-low-power devices
- **Burst Behavior:** No bursts, strictly rate-limited
- **Entropy:** Low-medium entropy

**Configuration:**
```cpp
ObfuscationProfile trickle_mode{
  .enabled = true,
  .max_padding_size = 100,
  .min_padding_size = 10,
  .min_prefix_size = 4,
  .max_prefix_size = 6,
  .heartbeat_min = 120s,    // Very infrequent heartbeats
  .heartbeat_max = 300s,
  .timing_jitter_enabled = true,
  .max_timing_jitter_ms = 500,  // High jitter for stealth
  .size_variance = 0.2f,  // Low variance (consistent small packets)
  .padding_distribution = {
    .small_weight = 100,  // Only small packets
    .medium_weight = 0,
    .large_weight = 0,
    .small_min = 10,
    .small_max = 100,
    .medium_min = 0,
    .medium_max = 0,
    .large_min = 0,
    .large_max = 0,
    .jitter_range = 10
  },
  .use_advanced_padding = true,
  .timing_jitter_model = TimingJitterModel::kPoisson,
  .timing_jitter_scale = 1.2f,
  .heartbeat_type = HeartbeatType::kMimicDNS,  // DNS-like heartbeats
  .heartbeat_timing_model = HeartbeatTimingModel::kExponential,
  .exponential_mean_seconds = 180.0f,  // Very infrequent (3 minute average)
  .exponential_max_gap = 600s,  // Up to 10 minutes
  .exponential_long_gap_probability = 0.3f,
  .heartbeat_entropy_normalization = false  // Low entropy for IoT-like traffic
};
```

**Special Features:**
- **DNS-Like Heartbeats:** Mimics DNS response structure to blend with common background traffic
- **Very Infrequent Heartbeats:** Exponential distribution with 3-minute average, up to 10-minute gaps
- Rate limiting: 10-50 kbit/s enforced at application layer
- Delay injection: 100-500ms between packets
- No retransmission bursts (use longer timeouts instead)

**Use Case:** Situations where any traffic spike triggers DPI alerts.

---

## Heartbeat Obfuscation

VEIL's heartbeat mechanism has been enhanced to prevent DPI detection through pattern analysis. Each mode uses different timing models and payload types to defeat various detection vectors.

### Heartbeat Timing Models

Three timing models are available via the `HeartbeatTimingModel` enum:

#### 1. Uniform Distribution (kUniform)
- **Behavior:** Classic uniform random distribution between `heartbeat_min` and `heartbeat_max`
- **Use Case:** Backward compatibility, basic unpredictability
- **Detection Resistance:** Limited - statistical analysis can still identify periodicity

#### 2. Exponential Distribution (kExponential)
- **Behavior:** Uses exponential distribution with configurable mean and occasional long gaps
- **Formula:** `interval = -mean * ln(1 - U)` where U ∈ [0,1)
- **Configuration Parameters:**
  - `exponential_mean_seconds`: Average interval in seconds
  - `exponential_max_gap`: Maximum gap duration for long pauses
  - `exponential_long_gap_probability`: Probability (0.0-1.0) of triggering a long gap
- **Detection Resistance:** Excellent - chaotic timing defeats autocorrelation analysis
- **Used By:** IoT Mimic, QUIC-Like, Trickle modes

**Example:** With mean=15s, max_gap=60s, probability=0.15:
- Most intervals follow exponential distribution around 15s
- 15% of the time, random gap between 0-60s is inserted
- No predictable periodicity

#### 3. Burst Mode (kBurst)
- **Behavior:** Sends multiple heartbeats rapidly in bursts, then long silence
- **Configuration Parameters:**
  - `burst_heartbeat_count_min/max`: Number of heartbeats per burst
  - `burst_silence_min/max`: Silence duration between bursts
  - `burst_interval`: Delay between heartbeats within a burst
- **Detection Resistance:** Excellent - breaks temporal correlation patterns
- **Used By:** Random-Noise mode

**Example:** With count=[2,4], silence=[90s,240s], interval=500ms:
- Sends 2-4 heartbeats at 500ms intervals (a 1-2 second burst)
- Then silent for 90-240 seconds
- Pattern is completely non-periodic

### Heartbeat Payload Types

Eight payload types are available via the `HeartbeatType` enum:

| Type | Description | Size | Detection Resistance |
|------|-------------|------|---------------------|
| **kEmpty** | Minimal empty heartbeat | ~8 bytes | Low (predictable size) |
| **kTimestamp** | Contains timestamp only | 8 bytes | Low (fixed size) |
| **kIoTSensor** | IoT sensor data (temp/humidity/battery) | 24 bytes | Medium (structured but varied) |
| **kGenericTelemetry** | Generic telemetry pattern | 24 bytes | Medium (structured but varied) |
| **kRandomSize** | Random payload size | 8-200 bytes | **Excellent** (defeats size fingerprinting) |
| **kMimicDNS** | DNS response structure | Variable | **Excellent** (blends with DNS traffic) |
| **kMimicSTUN** | STUN binding response (RFC 5389) | Variable | **Excellent** (blends with WebRTC) |
| **kMimicRTP** | RTP keepalive packet (RFC 3550) | Variable | **Excellent** (blends with VoIP) |

### Detection Vectors Addressed

The enhanced heartbeat system addresses three main detection vectors identified in issue #22:

1. **Regular Timing Pattern**
   - ❌ Old: Uniform distribution [5s, 15s] created periodic traffic
   - ✅ New: Exponential and burst modes eliminate periodicity

2. **Fixed Payload Structure**
   - ❌ Old: IoT payload had predictable 24-byte structure
   - ✅ New: Random-size and protocol-mimic payloads vary structure

3. **Encrypted Size Pattern**
   - ❌ Old: Heartbeat packets had consistent sizes
   - ✅ New: Variable payload types defeat size-based fingerprinting

### Configuration Summary by Mode

| Mode | Timing Model | Payload Type | Key Parameters |
|------|-------------|--------------|----------------|
| **IoT Mimic** | Exponential | IoTSensor | mean=15s, max_gap=60s, prob=15% |
| **QUIC-Like** | Exponential | RandomSize | mean=45s, max_gap=180s, prob=20% |
| **Random Noise** | Burst | RandomSize | burst=2-4, silence=90-240s |
| **Trickle** | Exponential | MimicDNS | mean=180s, max_gap=600s, prob=30% |

## Implementation Details

### 1. Mode Selection API

Add to `ObfuscationProfile`:

```cpp
enum class DPIBypassMode : std::uint8_t {
  kIoTMimic = 0,
  kQUICLike = 1,
  kRandomNoise = 2,
  kTrickle = 3,
  kCustom = 255  // User-defined profile
};

// Factory function to create profile for a given mode
ObfuscationProfile create_dpi_mode_profile(DPIBypassMode mode);

// Get human-readable mode name
const char* dpi_mode_to_string(DPIBypassMode mode);

// Parse mode from string
std::optional<DPIBypassMode> dpi_mode_from_string(const std::string& str);
```

### 2. Rate Limiting for Trickle Mode

New component: `src/transport/rate_limiter.h`

```cpp
class TokenBucketRateLimiter {
 public:
  explicit TokenBucketRateLimiter(std::uint32_t rate_bps, std::uint32_t burst_bytes);

  // Check if we can send N bytes now
  bool can_send(std::uint32_t bytes);

  // Consume N bytes from bucket (call after sending)
  void consume(std::uint32_t bytes);

  // Get delay until N bytes can be sent (in milliseconds)
  std::uint32_t delay_until_ready(std::uint32_t bytes) const;

 private:
  std::uint32_t rate_bps_;
  std::uint32_t burst_bytes_;
  std::uint32_t tokens_;
  std::chrono::steady_clock::time_point last_refill_;
};
```

### 3. GUI Integration

Add to `SettingsWidget`:

```cpp
// DPI Bypass Mode Selection
QComboBox* dpiModeCombo_;
QLabel* dpiModeDescription_;

// Mode descriptions
static constexpr const char* kIoTMimicDesc =
  "IoT Mimic: Simulates smart sensor traffic. Good balance of stealth and performance.";
static constexpr const char* kQUICLikeDesc =
  "QUIC-Like: Mimics modern HTTP/3 traffic. Best for high-throughput scenarios.";
static constexpr const char* kRandomNoiseDesc =
  "Random-Noise: Maximum unpredictability. Use in extreme censorship scenarios.";
static constexpr const char* kTrickleDesc =
  "Trickle: Low-and-slow traffic. Maximum stealth but limited bandwidth (10-50 kbit/s).";
```

### 4. IPC Protocol Extension

Add to `ipc_protocol.h`:

```cpp
enum class DPIBypassMode : std::uint8_t {
  kIoTMimic = 0,
  kQUICLike = 1,
  kRandomNoise = 2,
  kTrickle = 3
};

struct ConnectionConfig {
  // ... existing fields ...
  DPIBypassMode dpi_mode{DPIBypassMode::kIoTMimic};
};

struct DiagnosticsData {
  // ... existing fields ...
  std::string active_dpi_mode;
  ObfuscationMetrics obfuscation;  // Already exists
};
```

## Testing and Validation

### Traffic Pattern Analysis

For each mode, validate:

1. **Packet Size Distribution**
   - Plot histogram of packet sizes
   - Verify matches expected distribution for mode

2. **Inter-Packet Timing**
   - Plot timing intervals
   - Check for unintended patterns

3. **Entropy Analysis**
   - Measure payload entropy
   - Ensure high entropy for all modes

4. **DPI Evasion Tests**
   - Test against known DPI systems (nDPI, Snort rules)
   - Verify no static signatures detected

### Performance Benchmarks

- **IoT Mimic:** Should achieve 80-100% of baseline throughput
- **QUIC-Like:** Should achieve 90-100% of baseline throughput
- **Random-Noise:** May have 70-90% of baseline due to overhead
- **Trickle:** Intentionally limited to 10-50 kbit/s

## Security Considerations

1. **Mode Switching:** Changing modes should trigger session rekeying to avoid correlation
2. **Fingerprinting:** Each mode should avoid predictable patterns across sessions
3. **Replay Protection:** Applies regardless of mode
4. **Traffic Analysis Resistance:** Long-term observation should not reveal VPN usage

## Future Enhancements

1. **Adaptive Mode Selection:** Automatically switch modes based on detected DPI
2. **Mode Chaining:** Alternate between modes mid-session
3. **Machine Learning Evasion:** Train adversarial models to evade ML-based DPI
4. **Custom Mode Builder:** GUI for creating user-defined profiles

## DPI Evasion Comparison

### What Each Mode Evades

| DPI System Type | IoT Mimic | QUIC-Like | Random Noise | Trickle |
|-----------------|-----------|-----------|--------------|---------|
| **Statistical Analysis** | ✅ Good | ✅ Excellent | ✅ Excellent | ✅ Good |
| **Protocol Fingerprinting** | ❌ Limited | ✅ **Yes (WebSocket)** | ❌ Limited | ❌ Limited |
| **Timing-based Detection** | ✅ Good | ✅ Good | ✅ Excellent | ✅ Excellent |
| **Heartbeat Pattern Detection** | ✅ **Excellent** | ✅ **Excellent** | ✅ **Excellent** | ✅ **Excellent** |
| **Size-based Detection** | ✅ Good | ✅ Excellent | ✅ Excellent | ⚠️ Limited (intentionally small) |
| **Behavioral Heuristics** | ✅ Good | ✅ Good | ⚠️ May look suspicious | ✅ Excellent |

**Note:** All modes now use non-periodic heartbeat timing to prevent pattern-based detection (Issue #22).

### Protocol Wrapper Status

- **IoT Mimic:** Statistical shaping only (no protocol headers)
- **QUIC-Like:** ✅ **WebSocket wrapper enabled** (real RFC 6455 headers)
- **Random Noise:** Statistical shaping only (no protocol headers)
- **Trickle:** Statistical shaping only (no protocol headers)

### Implementation Notes

**QUIC-Like Mode WebSocket Wrapper:**
- Wraps each VEIL packet in a WebSocket binary frame
- Uses proper masking for client-to-server direction
- Adds 2-14 bytes overhead per packet (minimal impact)
- DPI sees: `FIN=1, Opcode=Binary(0x2), Masked=1, Payload=<VEIL packet>`

## References

- [Traffic Obfuscation Techniques](https://www.ndss-symposium.org/ndss-paper/how-china-detects-and-blocks-shadowsocks/)
- [WebSocket Protocol (RFC 6455)](https://www.rfc-editor.org/rfc/rfc6455.html)
- [QUIC Protocol Specification](https://www.rfc-editor.org/rfc/rfc9000.html)
- [IoT Traffic Patterns Analysis](https://ieeexplore.ieee.org/document/8424631)
