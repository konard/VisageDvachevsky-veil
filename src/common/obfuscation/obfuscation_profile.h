#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace veil::obfuscation {

// Profile seed size (32 bytes for deterministic obfuscation).
constexpr std::size_t kProfileSeedSize = 32;

// Padding size class for traffic morphing.
enum class PaddingSizeClass : std::uint8_t {
  kSmall = 0,   // 0-100 bytes, typical for keepalives/ACKs
  kMedium = 1,  // 100-400 bytes, typical for small requests
  kLarge = 2,   // 400-1000 bytes, typical for data transfer
};

// Padding distribution weights (must sum to 100).
struct PaddingDistribution {
  std::uint8_t small_weight{40};   // Weight for small packets (0-100)
  std::uint8_t medium_weight{40};  // Weight for medium packets (100-400)
  std::uint8_t large_weight{20};   // Weight for large packets (400-1000)

  // Size ranges for each class.
  std::uint16_t small_min{0};
  std::uint16_t small_max{100};
  std::uint16_t medium_min{100};
  std::uint16_t medium_max{400};
  std::uint16_t large_min{400};
  std::uint16_t large_max{1000};

  // Padding jitter range (±N bytes).
  std::uint16_t jitter_range{20};
};

// Timing jitter model type.
enum class TimingJitterModel : std::uint8_t {
  kUniform = 0,      // Uniform random distribution
  kPoisson = 1,      // Poisson distribution (network-like)
  kExponential = 2,  // Exponential distribution (bursty)
};

// Heartbeat timing model for temporal obfuscation.
enum class HeartbeatTimingModel : std::uint8_t {
  kUniform = 0,       // Uniform random distribution [min, max]
  kExponential = 1,   // Exponential distribution (chaotic, with occasional long gaps)
  kBurst = 2,         // Burst mode: multiple heartbeats quickly, then long silence
};

// Heartbeat payload type for semantic modeling.
enum class HeartbeatType : std::uint8_t {
  kEmpty = 0,           // Empty heartbeat (minimal)
  kTimestamp = 1,       // Contains timestamp only
  kIoTSensor = 2,       // IoT-like sensor data (temp/humidity/battery)
  kGenericTelemetry = 3,// Generic telemetry pattern
  kRandomSize = 4,      // Random size payload (8-200 bytes)
  kMimicDNS = 5,        // Mimic DNS response structure
  kMimicSTUN = 6,       // Mimic STUN binding response
  kMimicRTP = 7,        // Mimic RTP keepalive packet
};

// Protocol wrapper type for DPI evasion.
// Wrappers add legitimate protocol headers around VEIL packets.
enum class ProtocolWrapperType : std::uint8_t {
  kNone = 0,       // No protocol wrapper (default)
  kWebSocket = 1,  // WebSocket binary frames (RFC 6455)
};

// DPI bypass mode presets for Windows GUI.
// Each mode represents a different traffic pattern for evading DPI systems.
enum class DPIBypassMode : std::uint8_t {
  kIoTMimic = 0,     // Simulates IoT sensor telemetry (balanced stealth/performance)
  kQUICLike = 1,     // Mimics QUIC/HTTP3 traffic (high throughput)
  kRandomNoise = 2,  // Maximum entropy and unpredictability (extreme stealth)
  kTrickle = 3,      // Low-and-slow traffic (maximum stealth, limited bandwidth)
  kCustom = 255      // User-defined profile
};

// IoT-like sensor data template for heartbeat payloads.
struct IoTSensorTemplate {
  float temp_min{18.0f};
  float temp_max{25.0f};
  float humidity_min{40.0f};
  float humidity_max{70.0f};
  float battery_min{3.0f};
  float battery_max{4.2f};
  std::uint8_t device_id{0};  // Randomized per session
};

// Obfuscation profile configuration.
// Controls padding, prefix, timing jitter, and heartbeat behavior.
struct ObfuscationProfile {
  // Profile seed for deterministic padding/prefix generation.
  // If empty/zeroed, generates random seed on first use.
  std::array<std::uint8_t, kProfileSeedSize> profile_seed{};

  // Whether obfuscation is enabled.
  bool enabled{true};

  // Maximum padding size in bytes (added to each packet).
  std::uint16_t max_padding_size{400};

  // Minimum padding size in bytes.
  std::uint16_t min_padding_size{0};

  // Random prefix size range (4-12 bytes based on profile_seed + seq).
  std::uint8_t min_prefix_size{4};
  std::uint8_t max_prefix_size{12};

  // Heartbeat interval range for idle traffic.
  std::chrono::seconds heartbeat_min{5};
  std::chrono::seconds heartbeat_max{15};

  // Enable timing jitter for packet sends.
  bool timing_jitter_enabled{true};

  // Maximum timing jitter in milliseconds.
  std::uint16_t max_timing_jitter_ms{50};

  // Size variance: target different packet size distributions.
  // 0.0 = constant size, 1.0 = maximum variance.
  float size_variance{0.5f};

  // Padding distribution configuration.
  PaddingDistribution padding_distribution{};

  // Enable advanced padding distribution (uses padding_distribution config).
  bool use_advanced_padding{false};

  // Timing jitter model.
  TimingJitterModel timing_jitter_model{TimingJitterModel::kPoisson};

  // Timing jitter scale factor (multiplier for base jitter).
  float timing_jitter_scale{1.0f};

  // Heartbeat configuration.
  HeartbeatType heartbeat_type{HeartbeatType::kIoTSensor};

  // Heartbeat timing model (controls temporal distribution).
  HeartbeatTimingModel heartbeat_timing_model{HeartbeatTimingModel::kUniform};

  // IoT sensor template for heartbeat payloads.
  IoTSensorTemplate iot_sensor_template{};

  // Enable entropy normalization for heartbeat messages.
  bool heartbeat_entropy_normalization{true};

  // Burst mode configuration (only used when heartbeat_timing_model == kBurst).
  std::uint8_t burst_heartbeat_count_min{3};   // Minimum heartbeats per burst
  std::uint8_t burst_heartbeat_count_max{5};   // Maximum heartbeats per burst
  std::chrono::seconds burst_silence_min{30};  // Minimum silence between bursts
  std::chrono::seconds burst_silence_max{60};  // Maximum silence between bursts
  std::chrono::milliseconds burst_interval{200}; // Interval between heartbeats in a burst

  // Exponential timing configuration (only used when heartbeat_timing_model == kExponential).
  float exponential_mean_seconds{10.0f};       // Mean interval for exponential distribution
  std::chrono::seconds exponential_max_gap{120}; // Maximum gap (occasional long pauses)
  float exponential_long_gap_probability{0.1f}; // Probability of long gap (0.0-1.0)

  // Protocol wrapper configuration.
  ProtocolWrapperType protocol_wrapper{ProtocolWrapperType::kNone};

  // Client-to-server direction (for WebSocket masking).
  bool is_client_to_server{true};
};

// Obfuscation metrics for DPI/ML analysis.
struct ObfuscationMetrics {
  // Packet size statistics (sliding window).
  std::uint64_t packets_measured{0};
  double avg_packet_size{0.0};
  double packet_size_variance{0.0};
  double packet_size_stddev{0.0};
  std::uint16_t min_packet_size{0};
  std::uint16_t max_packet_size{0};

  // Packet size histogram (for DPI analysis).
  std::array<std::uint64_t, 16> size_histogram{};  // Buckets: 0-64, 64-128, ..., 960-1024+

  // Inter-packet timing statistics.
  double avg_interval_ms{0.0};
  double interval_variance{0.0};
  double interval_stddev{0.0};

  // Timing histogram (for pattern detection).
  std::array<std::uint64_t, 16> timing_histogram{};  // Buckets: 0-10ms, 10-20ms, ...

  // Heartbeat statistics.
  std::uint64_t heartbeats_sent{0};
  std::uint64_t heartbeats_received{0};
  double heartbeat_ratio{0.0};  // heartbeats / total packets

  // Padding statistics.
  std::uint64_t total_padding_bytes{0};
  double avg_padding_per_packet{0.0};

  // Padding size class distribution.
  std::uint64_t small_padding_count{0};
  std::uint64_t medium_padding_count{0};
  std::uint64_t large_padding_count{0};

  // Prefix statistics.
  std::uint64_t total_prefix_bytes{0};
  double avg_prefix_per_packet{0.0};

  // Jitter statistics.
  std::uint64_t jitter_applied_count{0};
  double avg_jitter_ms{0.0};
  double jitter_stddev{0.0};
};

// Configuration file section for obfuscation.
struct ObfuscationConfig {
  bool enabled{true};
  std::uint16_t max_padding_size{400};
  std::string profile_seed_hex;  // Hex-encoded seed, "auto" for random.
  std::chrono::seconds heartbeat_interval_min{5};
  std::chrono::seconds heartbeat_interval_max{15};
  bool enable_timing_jitter{true};
};

// Parse obfuscation config from key-value pairs.
// Typically called from INI/config file parser.
std::optional<ObfuscationConfig> parse_obfuscation_config(
    const std::string& enabled, const std::string& max_padding,
    const std::string& profile_seed, const std::string& heartbeat_min,
    const std::string& heartbeat_max, const std::string& timing_jitter);

// Convert ObfuscationConfig to runtime ObfuscationProfile.
ObfuscationProfile config_to_profile(const ObfuscationConfig& config);

// Generate a random profile seed.
std::array<std::uint8_t, kProfileSeedSize> generate_profile_seed();

// Compute deterministic padding size based on profile seed and sequence.
std::uint16_t compute_padding_size(const ObfuscationProfile& profile, std::uint64_t sequence);

// Compute padding size using advanced distribution (small/medium/large classes).
std::uint16_t compute_advanced_padding_size(const ObfuscationProfile& profile, std::uint64_t sequence);

// Determine which padding size class to use for a given sequence.
PaddingSizeClass compute_padding_class(const ObfuscationProfile& profile, std::uint64_t sequence);

// Compute deterministic prefix size based on profile seed and sequence.
std::uint8_t compute_prefix_size(const ObfuscationProfile& profile, std::uint64_t sequence);

// Compute timing jitter in milliseconds based on profile seed and sequence.
std::uint16_t compute_timing_jitter(const ObfuscationProfile& profile, std::uint64_t sequence);

// Compute timing jitter using Poisson/Exponential model.
// Returns timestamp offset in microseconds.
std::chrono::microseconds compute_timing_jitter_advanced(const ObfuscationProfile& profile,
                                                          std::uint64_t sequence);

// Calculate next send timestamp with jitter applied.
// base_ts: the base timestamp when packet would normally be sent.
// Returns adjusted timestamp with jitter.
std::chrono::steady_clock::time_point calculate_next_send_ts(
    const ObfuscationProfile& profile, std::uint64_t sequence,
    std::chrono::steady_clock::time_point base_ts);

// Compute heartbeat interval based on profile seed and timing model.
std::chrono::milliseconds compute_heartbeat_interval(const ObfuscationProfile& profile,
                                                      std::uint64_t heartbeat_count);

// Compute heartbeat interval using exponential distribution.
std::chrono::milliseconds compute_heartbeat_interval_exponential(const ObfuscationProfile& profile,
                                                                  std::uint64_t heartbeat_count);

// Compute heartbeat interval using burst mode.
// Returns interval to next heartbeat (short if in burst, long if between bursts).
// Also returns whether this is the start of a new burst via out parameter.
std::chrono::milliseconds compute_heartbeat_interval_burst(const ObfuscationProfile& profile,
                                                            std::uint64_t heartbeat_count,
                                                            bool& is_burst_start);

// Generate IoT-like sensor payload for heartbeat.
// Returns deterministic payload based on profile seed and sequence.
std::vector<std::uint8_t> generate_iot_heartbeat_payload(const ObfuscationProfile& profile,
                                                          std::uint64_t heartbeat_sequence);

// Generate generic telemetry payload for heartbeat.
std::vector<std::uint8_t> generate_telemetry_heartbeat_payload(const ObfuscationProfile& profile,
                                                                std::uint64_t heartbeat_sequence);

// Generate heartbeat payload based on configured heartbeat type.
std::vector<std::uint8_t> generate_heartbeat_payload(const ObfuscationProfile& profile,
                                                      std::uint64_t heartbeat_sequence);

// Generate random-size payload (8-200 bytes).
std::vector<std::uint8_t> generate_random_size_heartbeat_payload(const ObfuscationProfile& profile,
                                                                  std::uint64_t heartbeat_sequence);

// Generate DNS response-like payload.
std::vector<std::uint8_t> generate_dns_mimic_heartbeat_payload(const ObfuscationProfile& profile,
                                                                std::uint64_t heartbeat_sequence);

// Generate STUN binding response-like payload.
std::vector<std::uint8_t> generate_stun_mimic_heartbeat_payload(const ObfuscationProfile& profile,
                                                                 std::uint64_t heartbeat_sequence);

// Generate RTP keepalive-like payload.
std::vector<std::uint8_t> generate_rtp_mimic_heartbeat_payload(const ObfuscationProfile& profile,
                                                                std::uint64_t heartbeat_sequence);

// Apply entropy normalization to a buffer (fills gaps with pseudo-random data).
void apply_entropy_normalization(std::vector<std::uint8_t>& buffer,
                                  const std::array<std::uint8_t, kProfileSeedSize>& seed,
                                  std::uint64_t sequence);

// Update obfuscation metrics with a new packet measurement.
void update_metrics(ObfuscationMetrics& metrics, std::uint16_t packet_size,
                    std::uint16_t padding_size, std::uint16_t prefix_size,
                    double interval_ms, bool is_heartbeat);

// Reset obfuscation metrics.
void reset_metrics(ObfuscationMetrics& metrics);

// ============================================================================
// DPI Bypass Mode Factory Functions
// ============================================================================

// Create an obfuscation profile for a specific DPI bypass mode.
// Each mode has predefined parameters optimized for different evasion scenarios.
ObfuscationProfile create_dpi_mode_profile(DPIBypassMode mode);

// Get human-readable name for a DPI bypass mode.
const char* dpi_mode_to_string(DPIBypassMode mode);

// Parse DPI bypass mode from string.
std::optional<DPIBypassMode> dpi_mode_from_string(const std::string& str);

// Get description of a DPI bypass mode.
const char* dpi_mode_description(DPIBypassMode mode);

// Get human-readable name for a protocol wrapper type.
const char* protocol_wrapper_to_string(ProtocolWrapperType wrapper);

// Parse protocol wrapper type from string.
std::optional<ProtocolWrapperType> protocol_wrapper_from_string(const std::string& str);

}  // namespace veil::obfuscation
