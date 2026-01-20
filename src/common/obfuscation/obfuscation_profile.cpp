#include "common/obfuscation/obfuscation_profile.h"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>

#include "common/crypto/crypto_engine.h"
#include "common/crypto/random.h"

namespace veil::obfuscation {

namespace {

// Convert hex string to byte array.
bool hex_to_bytes(const std::string& hex, std::array<std::uint8_t, kProfileSeedSize>& out) {
  if (hex.size() != kProfileSeedSize * 2) {
    return false;
  }
  for (std::size_t i = 0; i < kProfileSeedSize; ++i) {
    const auto byte_str = hex.substr(i * 2, 2);
    std::uint8_t byte = 0;
    auto result = std::from_chars(byte_str.data(), byte_str.data() + 2, byte, 16);
    if (result.ec != std::errc{}) {
      return false;
    }
    out[i] = byte;
  }
  return true;
}

// Derive a deterministic value using HMAC of seed + counter.
std::uint64_t derive_value(const std::array<std::uint8_t, kProfileSeedSize>& seed,
                           std::uint64_t counter, const char* context) {
  // Create input: seed || counter || context.
  std::vector<std::uint8_t> input;
  input.reserve(seed.size() + 8 + std::strlen(context));
  input.insert(input.end(), seed.begin(), seed.end());
  for (int i = 7; i >= 0; --i) {
    input.push_back(static_cast<std::uint8_t>((counter >> (8 * i)) & 0xFF));
  }
  input.insert(input.end(), context, context + std::strlen(context));

  // HMAC with seed as key.
  auto hmac = crypto::hmac_sha256(seed, input);

  // Extract first 8 bytes as uint64.
  std::uint64_t value = 0;
  for (int i = 0; i < 8; ++i) {
    value = (value << 8) | hmac[static_cast<std::size_t>(i)];
  }
  return value;
}

}  // namespace

std::optional<ObfuscationConfig> parse_obfuscation_config(
    const std::string& enabled, const std::string& max_padding,
    const std::string& profile_seed, const std::string& heartbeat_min,
    const std::string& heartbeat_max, const std::string& timing_jitter) {
  ObfuscationConfig config;

  // Parse enabled.
  config.enabled = (enabled == "true" || enabled == "1" || enabled == "yes");

  // Parse max_padding_size.
  if (!max_padding.empty()) {
    int val = 0;
    auto result = std::from_chars(max_padding.data(), max_padding.data() + max_padding.size(), val);
    if (result.ec == std::errc{} && val >= 0 && val <= 65535) {
      config.max_padding_size = static_cast<std::uint16_t>(val);
    }
  }

  // Parse profile_seed.
  config.profile_seed_hex = profile_seed;

  // Parse heartbeat intervals.
  if (!heartbeat_min.empty()) {
    int val = 0;
    auto result =
        std::from_chars(heartbeat_min.data(), heartbeat_min.data() + heartbeat_min.size(), val);
    if (result.ec == std::errc{} && val >= 0) {
      config.heartbeat_interval_min = std::chrono::seconds(val);
    }
  }
  if (!heartbeat_max.empty()) {
    int val = 0;
    auto result =
        std::from_chars(heartbeat_max.data(), heartbeat_max.data() + heartbeat_max.size(), val);
    if (result.ec == std::errc{} && val >= 0) {
      config.heartbeat_interval_max = std::chrono::seconds(val);
    }
  }

  // Parse timing_jitter.
  config.enable_timing_jitter =
      (timing_jitter == "true" || timing_jitter == "1" || timing_jitter == "yes");

  return config;
}

ObfuscationProfile config_to_profile(const ObfuscationConfig& config) {
  ObfuscationProfile profile;
  profile.enabled = config.enabled;
  profile.max_padding_size = config.max_padding_size;
  profile.heartbeat_min = config.heartbeat_interval_min;
  profile.heartbeat_max = config.heartbeat_interval_max;
  profile.timing_jitter_enabled = config.enable_timing_jitter;

  // Parse or generate profile seed.
  if (config.profile_seed_hex.empty() || config.profile_seed_hex == "auto") {
    profile.profile_seed = generate_profile_seed();
  } else {
    if (!hex_to_bytes(config.profile_seed_hex, profile.profile_seed)) {
      // Invalid hex, generate random seed.
      profile.profile_seed = generate_profile_seed();
    }
  }

  return profile;
}

std::array<std::uint8_t, kProfileSeedSize> generate_profile_seed() {
  std::array<std::uint8_t, kProfileSeedSize> seed{};
  auto random = crypto::random_bytes(kProfileSeedSize);
  std::copy(random.begin(), random.end(), seed.begin());
  return seed;
}

std::uint16_t compute_padding_size(const ObfuscationProfile& profile, std::uint64_t sequence) {
  if (!profile.enabled || profile.max_padding_size == 0) {
    return 0;
  }

  const auto value = derive_value(profile.profile_seed, sequence, "padding");
  const auto range = static_cast<std::uint16_t>(profile.max_padding_size - profile.min_padding_size + 1);
  return static_cast<std::uint16_t>(profile.min_padding_size + static_cast<std::uint16_t>(value % range));
}

std::uint8_t compute_prefix_size(const ObfuscationProfile& profile, std::uint64_t sequence) {
  if (!profile.enabled) {
    return 0;
  }

  const auto value = derive_value(profile.profile_seed, sequence, "prefix");
  const auto range = static_cast<std::uint8_t>(profile.max_prefix_size - profile.min_prefix_size + 1);
  return static_cast<std::uint8_t>(profile.min_prefix_size + static_cast<std::uint8_t>(value % range));
}

std::uint16_t compute_timing_jitter(const ObfuscationProfile& profile, std::uint64_t sequence) {
  if (!profile.enabled || !profile.timing_jitter_enabled || profile.max_timing_jitter_ms == 0) {
    return 0;
  }

  const auto value = derive_value(profile.profile_seed, sequence, "jitter");
  return static_cast<std::uint16_t>(value % (profile.max_timing_jitter_ms + 1));
}

std::chrono::milliseconds compute_heartbeat_interval(const ObfuscationProfile& profile,
                                                      std::uint64_t heartbeat_count) {
  switch (profile.heartbeat_timing_model) {
    case HeartbeatTimingModel::kUniform: {
      // Original uniform random distribution.
      const auto min_ms =
          std::chrono::duration_cast<std::chrono::milliseconds>(profile.heartbeat_min).count();
      const auto max_ms =
          std::chrono::duration_cast<std::chrono::milliseconds>(profile.heartbeat_max).count();

      if (min_ms >= max_ms) {
        return std::chrono::milliseconds(min_ms);
      }

      const auto value = derive_value(profile.profile_seed, heartbeat_count, "heartbeat");
      const auto range = static_cast<std::uint64_t>(max_ms - min_ms + 1);
      return std::chrono::milliseconds(min_ms + static_cast<long long>(value % range));
    }

    case HeartbeatTimingModel::kExponential:
      return compute_heartbeat_interval_exponential(profile, heartbeat_count);

    case HeartbeatTimingModel::kBurst: {
      bool is_burst_start = false;
      return compute_heartbeat_interval_burst(profile, heartbeat_count, is_burst_start);
    }

    default:
      // Fallback to uniform.
      const auto min_ms =
          std::chrono::duration_cast<std::chrono::milliseconds>(profile.heartbeat_min).count();
      return std::chrono::milliseconds(min_ms);
  }
}

std::chrono::milliseconds compute_heartbeat_interval_exponential(const ObfuscationProfile& profile,
                                                                  std::uint64_t heartbeat_count) {
  // Use exponential distribution with occasional long gaps.
  // This creates chaotic, non-periodic timing that resists statistical analysis.

  // Derive two random values: one for the base interval, one for long gap decision.
  const auto base_value = derive_value(profile.profile_seed, heartbeat_count, "hb_exp");
  const auto gap_value = derive_value(profile.profile_seed, heartbeat_count, "hb_gap");

  // Normalize base_value to [0, 1).
  const auto normalized = static_cast<double>(base_value) / static_cast<double>(UINT64_MAX);

  // Check if this should be a long gap (based on probability).
  const auto gap_normalized = static_cast<double>(gap_value % 10000) / 10000.0;
  const bool use_long_gap = gap_normalized < static_cast<double>(profile.exponential_long_gap_probability);

  if (use_long_gap) {
    // Occasional long gap: uniform random in [mean, max_gap].
    const auto mean_ms = static_cast<long long>(profile.exponential_mean_seconds * 1000.0f);
    const auto max_gap_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(profile.exponential_max_gap).count();

    if (mean_ms >= max_gap_ms) {
      return std::chrono::milliseconds(max_gap_ms);
    }

    const auto range = static_cast<std::uint64_t>(max_gap_ms - mean_ms + 1);
    const auto offset = base_value % range;
    return std::chrono::milliseconds(mean_ms + static_cast<long long>(offset));
  }

  // Normal case: use exponential distribution.
  // Exponential CDF: F(x) = 1 - e^(-x/mean)
  // Inverse: x = -mean * ln(1 - U)
  const auto mean_ms = static_cast<double>(profile.exponential_mean_seconds * 1000.0f);
  const auto clamped = std::max(normalized, 1e-10);  // Avoid log(0).
  auto interval_ms = -mean_ms * std::log(1.0 - clamped);

  // Cap at a reasonable maximum (3x mean) to avoid extremely long waits.
  const auto cap_ms = mean_ms * 3.0;
  interval_ms = std::min(interval_ms, cap_ms);

  // Ensure minimum of 1 second to avoid too-frequent heartbeats.
  interval_ms = std::max(interval_ms, 1000.0);

  return std::chrono::milliseconds(static_cast<long long>(interval_ms));
}

std::chrono::milliseconds compute_heartbeat_interval_burst(const ObfuscationProfile& profile,
                                                            std::uint64_t heartbeat_count,
                                                            bool& is_burst_start) {
  // Burst mode: Send N heartbeats quickly, then go silent for a long period.
  // This breaks up regular timing patterns.

  // Determine burst size for this cycle.
  const auto burst_value = derive_value(profile.profile_seed, heartbeat_count / 100, "hb_burst_sz");
  const auto burst_range = static_cast<std::uint8_t>(
      profile.burst_heartbeat_count_max - profile.burst_heartbeat_count_min + 1);
  const auto burst_size = profile.burst_heartbeat_count_min +
                          static_cast<std::uint8_t>(burst_value % burst_range);

  // Determine position within the burst cycle.
  const auto burst_size_u64 = static_cast<std::uint64_t>(burst_size);
  const auto position_in_cycle = heartbeat_count % (burst_size_u64 + 1);

  if (position_in_cycle < burst_size_u64) {
    // We're in a burst - send heartbeats quickly.
    is_burst_start = (position_in_cycle == 0);
    return profile.burst_interval;
  } else {
    // We're between bursts - long silence.
    is_burst_start = false;
    const auto silence_value = derive_value(profile.profile_seed, heartbeat_count, "hb_silence");
    const auto silence_min_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(profile.burst_silence_min).count();
    const auto silence_max_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(profile.burst_silence_max).count();

    if (silence_min_ms >= silence_max_ms) {
      return std::chrono::milliseconds(silence_min_ms);
    }

    const auto range = static_cast<std::uint64_t>(silence_max_ms - silence_min_ms + 1);
    return std::chrono::milliseconds(silence_min_ms + static_cast<long long>(silence_value % range));
  }
}

PaddingSizeClass compute_padding_class(const ObfuscationProfile& profile, std::uint64_t sequence) {
  if (!profile.enabled || !profile.use_advanced_padding) {
    return PaddingSizeClass::kSmall;
  }

  const auto& dist = profile.padding_distribution;
  const auto total_weight = static_cast<std::uint16_t>(dist.small_weight + dist.medium_weight + dist.large_weight);
  if (total_weight == 0) {
    return PaddingSizeClass::kSmall;
  }

  const auto value = derive_value(profile.profile_seed, sequence, "padclass");
  const auto roll = static_cast<std::uint16_t>(value % total_weight);

  if (roll < dist.small_weight) {
    return PaddingSizeClass::kSmall;
  }
  if (roll < static_cast<std::uint16_t>(dist.small_weight + dist.medium_weight)) {
    return PaddingSizeClass::kMedium;
  }
  return PaddingSizeClass::kLarge;
}

std::uint16_t compute_advanced_padding_size(const ObfuscationProfile& profile, std::uint64_t sequence) {
  if (!profile.enabled) {
    return 0;
  }

  if (!profile.use_advanced_padding) {
    return compute_padding_size(profile, sequence);
  }

  const auto& dist = profile.padding_distribution;
  const auto padding_class = compute_padding_class(profile, sequence);

  std::uint16_t min_size = 0;
  std::uint16_t max_size = 0;

  switch (padding_class) {
    case PaddingSizeClass::kSmall:
      min_size = dist.small_min;
      max_size = dist.small_max;
      break;
    case PaddingSizeClass::kMedium:
      min_size = dist.medium_min;
      max_size = dist.medium_max;
      break;
    case PaddingSizeClass::kLarge:
      min_size = dist.large_min;
      max_size = dist.large_max;
      break;
  }

  if (min_size >= max_size) {
    return min_size;
  }

  // Get base size within the range.
  const auto value = derive_value(profile.profile_seed, sequence, "advpad");
  const auto range = static_cast<std::uint16_t>(max_size - min_size + 1);
  auto base_size = static_cast<std::uint16_t>(min_size + static_cast<std::uint16_t>(value % range));

  // Apply jitter if configured.
  if (dist.jitter_range > 0) {
    const auto jitter_value = derive_value(profile.profile_seed, sequence + 1000000, "padjit");
    const auto jitter_range_full = static_cast<std::uint16_t>(dist.jitter_range * 2 + 1);
    const auto jitter_offset = static_cast<std::int16_t>(jitter_value % jitter_range_full) -
                               static_cast<std::int16_t>(dist.jitter_range);

    // Apply jitter but clamp to valid range.
    const auto new_size = static_cast<std::int32_t>(base_size) + jitter_offset;
    base_size = static_cast<std::uint16_t>(
        std::clamp(new_size, static_cast<std::int32_t>(min_size), static_cast<std::int32_t>(max_size)));
  }

  return base_size;
}

std::chrono::microseconds compute_timing_jitter_advanced(const ObfuscationProfile& profile,
                                                          std::uint64_t sequence) {
  if (!profile.enabled || !profile.timing_jitter_enabled || profile.max_timing_jitter_ms == 0) {
    return std::chrono::microseconds(0);
  }

  const auto base_value = derive_value(profile.profile_seed, sequence, "advjit");

  // Normalize to [0, 1).
  const auto normalized = static_cast<double>(base_value) / static_cast<double>(UINT64_MAX);

  double jitter_ms = 0.0;
  const auto max_jitter = static_cast<double>(profile.max_timing_jitter_ms);

  switch (profile.timing_jitter_model) {
    case TimingJitterModel::kUniform:
      // Uniform distribution: jitter uniformly in [0, max_jitter].
      jitter_ms = normalized * max_jitter;
      break;

    case TimingJitterModel::kPoisson: {
      // Poisson-like: use inverse transform of exponential CDF.
      // -ln(1 - U) * lambda, where lambda is scaled to give expected value ~ max_jitter/2.
      const auto lambda = max_jitter / 2.0;
      // Avoid log(0) by clamping.
      const auto clamped = std::max(normalized, 1e-10);
      jitter_ms = -std::log(1.0 - clamped) * lambda;
      // Cap at max_jitter.
      jitter_ms = std::min(jitter_ms, max_jitter);
      break;
    }

    case TimingJitterModel::kExponential: {
      // Exponential distribution: -ln(1 - U) * mean.
      // More bursty than Poisson.
      const auto mean = max_jitter / 3.0;  // Lower mean for more bursty behavior.
      const auto clamped = std::max(normalized, 1e-10);
      jitter_ms = -std::log(1.0 - clamped) * mean;
      // Cap at max_jitter.
      jitter_ms = std::min(jitter_ms, max_jitter);
      break;
    }
  }

  // Apply scale factor.
  jitter_ms *= static_cast<double>(profile.timing_jitter_scale);

  // Convert to microseconds.
  return std::chrono::microseconds(static_cast<std::int64_t>(jitter_ms * 1000.0));
}

std::chrono::steady_clock::time_point calculate_next_send_ts(
    const ObfuscationProfile& profile, std::uint64_t sequence,
    std::chrono::steady_clock::time_point base_ts) {
  if (!profile.enabled || !profile.timing_jitter_enabled) {
    return base_ts;
  }

  const auto jitter = compute_timing_jitter_advanced(profile, sequence);
  return base_ts + jitter;
}

std::vector<std::uint8_t> generate_iot_heartbeat_payload(const ObfuscationProfile& profile,
                                                          std::uint64_t heartbeat_sequence) {
  std::vector<std::uint8_t> payload;
  payload.reserve(32);  // Typical IoT payload size.

  const auto& tmpl = profile.iot_sensor_template;

  // Generate deterministic "random" values based on seed and sequence.
  const auto temp_val = derive_value(profile.profile_seed, heartbeat_sequence, "iot_temp");
  const auto humidity_val = derive_value(profile.profile_seed, heartbeat_sequence, "iot_hum");
  const auto battery_val = derive_value(profile.profile_seed, heartbeat_sequence, "iot_bat");

  // Normalize to ranges.
  const auto temp_norm = static_cast<double>(temp_val % 10000) / 10000.0;
  const auto humidity_norm = static_cast<double>(humidity_val % 10000) / 10000.0;
  const auto battery_norm = static_cast<double>(battery_val % 10000) / 10000.0;

  const auto temperature = tmpl.temp_min + static_cast<float>(temp_norm * static_cast<double>(tmpl.temp_max - tmpl.temp_min));
  const auto humidity = tmpl.humidity_min + static_cast<float>(humidity_norm * static_cast<double>(tmpl.humidity_max - tmpl.humidity_min));
  const auto battery = tmpl.battery_min + static_cast<float>(battery_norm * static_cast<double>(tmpl.battery_max - tmpl.battery_min));

  // IoT packet structure (simplified):
  // [0]: Message type (0x01 = sensor data)
  // [1]: Device ID
  // [2-3]: Sequence number (big-endian, low 16 bits)
  // [4-7]: Temperature (float, big-endian IEEE 754)
  // [8-11]: Humidity (float, big-endian IEEE 754)
  // [12-15]: Battery voltage (float, big-endian IEEE 754)
  // [16-19]: Timestamp offset (4 bytes)
  // [20-23]: Checksum placeholder (4 bytes)

  payload.push_back(0x01);  // Message type.
  payload.push_back(tmpl.device_id);

  // Sequence (16-bit).
  const auto seq16 = static_cast<std::uint16_t>(heartbeat_sequence & 0xFFFF);
  payload.push_back(static_cast<std::uint8_t>((seq16 >> 8) & 0xFF));
  payload.push_back(static_cast<std::uint8_t>(seq16 & 0xFF));

  // Helper to write float as big-endian bytes.
  auto write_float = [&payload](float value) {
    std::uint32_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    payload.push_back(static_cast<std::uint8_t>((bits >> 24) & 0xFF));
    payload.push_back(static_cast<std::uint8_t>((bits >> 16) & 0xFF));
    payload.push_back(static_cast<std::uint8_t>((bits >> 8) & 0xFF));
    payload.push_back(static_cast<std::uint8_t>(bits & 0xFF));
  };

  write_float(temperature);
  write_float(humidity);
  write_float(battery);

  // Timestamp offset (deterministic pseudo-random).
  const auto ts_offset = static_cast<std::uint32_t>(derive_value(profile.profile_seed, heartbeat_sequence, "iot_ts") & 0xFFFFFFFF);
  payload.push_back(static_cast<std::uint8_t>((ts_offset >> 24) & 0xFF));
  payload.push_back(static_cast<std::uint8_t>((ts_offset >> 16) & 0xFF));
  payload.push_back(static_cast<std::uint8_t>((ts_offset >> 8) & 0xFF));
  payload.push_back(static_cast<std::uint8_t>(ts_offset & 0xFF));

  // Simple checksum (XOR of all bytes).
  std::uint32_t checksum = 0;
  for (const auto& byte : payload) {
    checksum ^= byte;
    checksum = (checksum << 1) | (checksum >> 31);  // Rotate left.
  }
  payload.push_back(static_cast<std::uint8_t>((checksum >> 24) & 0xFF));
  payload.push_back(static_cast<std::uint8_t>((checksum >> 16) & 0xFF));
  payload.push_back(static_cast<std::uint8_t>((checksum >> 8) & 0xFF));
  payload.push_back(static_cast<std::uint8_t>(checksum & 0xFF));

  return payload;
}

std::vector<std::uint8_t> generate_telemetry_heartbeat_payload(const ObfuscationProfile& profile,
                                                                std::uint64_t heartbeat_sequence) {
  std::vector<std::uint8_t> payload;
  payload.reserve(24);

  // Generic telemetry structure:
  // [0-3]: Magic (0x54454C4D = "TELM")
  // [4-5]: Version (0x0001)
  // [6-7]: Payload length
  // [8-15]: Sequence number
  // [16-23]: Timestamp placeholder

  payload.push_back(0x54);  // 'T'
  payload.push_back(0x45);  // 'E'
  payload.push_back(0x4C);  // 'L'
  payload.push_back(0x4D);  // 'M'

  payload.push_back(0x00);  // Version high.
  payload.push_back(0x01);  // Version low.

  payload.push_back(0x00);  // Length high.
  payload.push_back(0x10);  // Length low (16 bytes following).

  // Sequence number.
  for (int i = 7; i >= 0; --i) {
    payload.push_back(static_cast<std::uint8_t>((heartbeat_sequence >> (8 * i)) & 0xFF));
  }

  // Pseudo-timestamp.
  const auto ts = derive_value(profile.profile_seed, heartbeat_sequence, "tel_ts");
  for (int i = 7; i >= 0; --i) {
    payload.push_back(static_cast<std::uint8_t>((ts >> (8 * i)) & 0xFF));
  }

  return payload;
}

std::vector<std::uint8_t> generate_heartbeat_payload(const ObfuscationProfile& profile,
                                                      std::uint64_t heartbeat_sequence) {
  switch (profile.heartbeat_type) {
    case HeartbeatType::kEmpty:
      return {};

    case HeartbeatType::kTimestamp: {
      std::vector<std::uint8_t> payload;
      payload.reserve(8);
      const auto ts = derive_value(profile.profile_seed, heartbeat_sequence, "hb_ts");
      for (int i = 7; i >= 0; --i) {
        payload.push_back(static_cast<std::uint8_t>((ts >> (8 * i)) & 0xFF));
      }
      return payload;
    }

    case HeartbeatType::kIoTSensor:
      return generate_iot_heartbeat_payload(profile, heartbeat_sequence);

    case HeartbeatType::kGenericTelemetry:
      return generate_telemetry_heartbeat_payload(profile, heartbeat_sequence);

    case HeartbeatType::kRandomSize:
      return generate_random_size_heartbeat_payload(profile, heartbeat_sequence);

    case HeartbeatType::kMimicDNS:
      return generate_dns_mimic_heartbeat_payload(profile, heartbeat_sequence);

    case HeartbeatType::kMimicSTUN:
      return generate_stun_mimic_heartbeat_payload(profile, heartbeat_sequence);

    case HeartbeatType::kMimicRTP:
      return generate_rtp_mimic_heartbeat_payload(profile, heartbeat_sequence);
  }

  return {};
}

std::vector<std::uint8_t> generate_random_size_heartbeat_payload(const ObfuscationProfile& profile,
                                                                  std::uint64_t heartbeat_sequence) {
  // Generate payload with random size between 8 and 200 bytes.
  // This defeats size-based pattern detection.

  const auto size_value = derive_value(profile.profile_seed, heartbeat_sequence, "hb_rand_sz");
  const auto size = 8 + static_cast<std::size_t>(size_value % (200 - 8 + 1));

  std::vector<std::uint8_t> payload;
  payload.reserve(size);

  // Fill with pseudo-random data based on seed.
  for (std::size_t i = 0; i < size; ++i) {
    const auto byte_value = derive_value(profile.profile_seed, heartbeat_sequence + i, "hb_rand_b");
    payload.push_back(static_cast<std::uint8_t>(byte_value & 0xFF));
  }

  return payload;
}

std::vector<std::uint8_t> generate_dns_mimic_heartbeat_payload(const ObfuscationProfile& profile,
                                                                std::uint64_t heartbeat_sequence) {
  // Mimic DNS response structure (simplified).
  // Real DNS responses have:
  // - 12 byte header
  // - Question section
  // - Answer section (variable)
  //
  // We'll create a minimal response-like structure.

  std::vector<std::uint8_t> payload;
  payload.reserve(64);

  // DNS Header (12 bytes).
  // Transaction ID (2 bytes).
  const auto txid = static_cast<std::uint16_t>(
      derive_value(profile.profile_seed, heartbeat_sequence, "dns_txid") & 0xFFFF);
  payload.push_back(static_cast<std::uint8_t>((txid >> 8) & 0xFF));
  payload.push_back(static_cast<std::uint8_t>(txid & 0xFF));

  // Flags (2 bytes): Standard query response, no error.
  payload.push_back(0x81);  // QR=1, Opcode=0, AA=0, TC=0, RD=1
  payload.push_back(0x80);  // RA=1, Z=0, RCODE=0

  // QDCOUNT (2 bytes): 1 question.
  payload.push_back(0x00);
  payload.push_back(0x01);

  // ANCOUNT (2 bytes): 1 answer.
  payload.push_back(0x00);
  payload.push_back(0x01);

  // NSCOUNT, ARCOUNT (4 bytes): 0.
  payload.push_back(0x00);
  payload.push_back(0x00);
  payload.push_back(0x00);
  payload.push_back(0x00);

  // Question section (variable, we'll use ~20 bytes for a simple domain).
  // Format: <length>label<length>label...<0> <type> <class>
  // Example: "\x07example\x03com\x00" for "example.com"
  payload.push_back(0x07);  // Length of "example"
  for (char c : std::string("example")) {
    payload.push_back(static_cast<std::uint8_t>(c));
  }
  payload.push_back(0x03);  // Length of "com"
  for (char c : std::string("com")) {
    payload.push_back(static_cast<std::uint8_t>(c));
  }
  payload.push_back(0x00);  // End of domain name

  // QTYPE (2 bytes): A record (0x0001).
  payload.push_back(0x00);
  payload.push_back(0x01);

  // QCLASS (2 bytes): IN (0x0001).
  payload.push_back(0x00);
  payload.push_back(0x01);

  // Answer section (variable, we'll add a simple A record).
  // Name (2 bytes): Pointer to question name (compression).
  payload.push_back(0xC0);
  payload.push_back(0x0C);

  // TYPE (2 bytes): A.
  payload.push_back(0x00);
  payload.push_back(0x01);

  // CLASS (2 bytes): IN.
  payload.push_back(0x00);
  payload.push_back(0x01);

  // TTL (4 bytes): Random TTL.
  const auto ttl = static_cast<std::uint32_t>(
      derive_value(profile.profile_seed, heartbeat_sequence, "dns_ttl") & 0xFFFFFFFF);
  payload.push_back(static_cast<std::uint8_t>((ttl >> 24) & 0xFF));
  payload.push_back(static_cast<std::uint8_t>((ttl >> 16) & 0xFF));
  payload.push_back(static_cast<std::uint8_t>((ttl >> 8) & 0xFF));
  payload.push_back(static_cast<std::uint8_t>(ttl & 0xFF));

  // RDLENGTH (2 bytes): 4 (IPv4 address).
  payload.push_back(0x00);
  payload.push_back(0x04);

  // RDATA (4 bytes): Random IP address.
  const auto ip = static_cast<std::uint32_t>(
      derive_value(profile.profile_seed, heartbeat_sequence, "dns_ip") & 0xFFFFFFFF);
  payload.push_back(static_cast<std::uint8_t>((ip >> 24) & 0xFF));
  payload.push_back(static_cast<std::uint8_t>((ip >> 16) & 0xFF));
  payload.push_back(static_cast<std::uint8_t>((ip >> 8) & 0xFF));
  payload.push_back(static_cast<std::uint8_t>(ip & 0xFF));

  return payload;
}

std::vector<std::uint8_t> generate_stun_mimic_heartbeat_payload(const ObfuscationProfile& profile,
                                                                 std::uint64_t heartbeat_sequence) {
  // Mimic STUN Binding Response structure.
  // STUN message format (RFC 5389):
  // - 20 byte header
  // - Attributes (variable)
  //
  // Header format:
  // 0-1: Message Type (0x0101 = Binding Response Success)
  // 2-3: Message Length (payload length, excluding 20-byte header)
  // 4-7: Magic Cookie (0x2112A442)
  // 8-19: Transaction ID (96 bits)

  std::vector<std::uint8_t> payload;
  payload.reserve(48);

  // Message Type (2 bytes): Binding Response Success (0x0101).
  payload.push_back(0x01);
  payload.push_back(0x01);

  // Message Length (2 bytes): Will be filled at the end.
  const auto length_pos = payload.size();
  payload.push_back(0x00);
  payload.push_back(0x00);

  // Magic Cookie (4 bytes): 0x2112A442.
  payload.push_back(0x21);
  payload.push_back(0x12);
  payload.push_back(0xA4);
  payload.push_back(0x42);

  // Transaction ID (12 bytes): Random.
  const auto txid1 = derive_value(profile.profile_seed, heartbeat_sequence, "stun_tx1");
  const auto txid2 = derive_value(profile.profile_seed, heartbeat_sequence, "stun_tx2");
  for (int i = 7; i >= 0; --i) {
    payload.push_back(static_cast<std::uint8_t>((txid1 >> (8 * i)) & 0xFF));
  }
  for (int i = 3; i >= 0; --i) {
    payload.push_back(static_cast<std::uint8_t>((txid2 >> (8 * i)) & 0xFF));
  }

  // Add XOR-MAPPED-ADDRESS attribute (8 bytes total: 4 header + 4 data).
  // Type (2 bytes): 0x0020 (XOR-MAPPED-ADDRESS).
  payload.push_back(0x00);
  payload.push_back(0x20);

  // Length (2 bytes): 8 (family + port + address).
  payload.push_back(0x00);
  payload.push_back(0x08);

  // Family (1 byte): 0x01 (IPv4).
  payload.push_back(0x01);

  // X-Port (2 bytes): Port XORed with magic cookie high 16 bits.
  const auto port = static_cast<std::uint16_t>(
      derive_value(profile.profile_seed, heartbeat_sequence, "stun_port") & 0xFFFF);
  const auto xport = port ^ 0x2112;
  payload.push_back(static_cast<std::uint8_t>((xport >> 8) & 0xFF));
  payload.push_back(static_cast<std::uint8_t>(xport & 0xFF));

  // X-Address (4 bytes): IP XORed with magic cookie.
  const auto ip = static_cast<std::uint32_t>(
      derive_value(profile.profile_seed, heartbeat_sequence, "stun_ip") & 0xFFFFFFFF);
  const auto xip = ip ^ 0x2112A442;
  payload.push_back(static_cast<std::uint8_t>((xip >> 24) & 0xFF));
  payload.push_back(static_cast<std::uint8_t>((xip >> 16) & 0xFF));
  payload.push_back(static_cast<std::uint8_t>((xip >> 8) & 0xFF));
  payload.push_back(static_cast<std::uint8_t>(xip & 0xFF));

  // Padding (1 byte) to align to 4-byte boundary.
  payload.push_back(0x00);

  // Update message length (payload size - 20 byte header).
  const auto msg_length = static_cast<std::uint16_t>(payload.size() - 20);
  payload[length_pos] = static_cast<std::uint8_t>((msg_length >> 8) & 0xFF);
  payload[length_pos + 1] = static_cast<std::uint8_t>(msg_length & 0xFF);

  return payload;
}

std::vector<std::uint8_t> generate_rtp_mimic_heartbeat_payload(const ObfuscationProfile& profile,
                                                                std::uint64_t heartbeat_sequence) {
  // Mimic RTP (Real-time Transport Protocol) keepalive packet.
  // RTP header is 12 bytes minimum.
  // Format (RFC 3550):
  // 0: V(2) P(1) X(1) CC(4)
  // 1: M(1) PT(7)
  // 2-3: Sequence number
  // 4-7: Timestamp
  // 8-11: SSRC

  std::vector<std::uint8_t> payload;
  payload.reserve(12);

  // V=2, P=0, X=0, CC=0.
  payload.push_back(0x80);

  // M=0, PT=96 (dynamic payload type, common for custom codecs).
  payload.push_back(96);

  // Sequence number (2 bytes).
  const auto seq = static_cast<std::uint16_t>(heartbeat_sequence & 0xFFFF);
  payload.push_back(static_cast<std::uint8_t>((seq >> 8) & 0xFF));
  payload.push_back(static_cast<std::uint8_t>(seq & 0xFF));

  // Timestamp (4 bytes): Deterministic based on sequence.
  const auto ts = static_cast<std::uint32_t>(
      derive_value(profile.profile_seed, heartbeat_sequence, "rtp_ts") & 0xFFFFFFFF);
  payload.push_back(static_cast<std::uint8_t>((ts >> 24) & 0xFF));
  payload.push_back(static_cast<std::uint8_t>((ts >> 16) & 0xFF));
  payload.push_back(static_cast<std::uint8_t>((ts >> 8) & 0xFF));
  payload.push_back(static_cast<std::uint8_t>(ts & 0xFF));

  // SSRC (4 bytes): Synchronization source identifier.
  const auto ssrc = static_cast<std::uint32_t>(
      derive_value(profile.profile_seed, heartbeat_sequence, "rtp_ssrc") & 0xFFFFFFFF);
  payload.push_back(static_cast<std::uint8_t>((ssrc >> 24) & 0xFF));
  payload.push_back(static_cast<std::uint8_t>((ssrc >> 16) & 0xFF));
  payload.push_back(static_cast<std::uint8_t>((ssrc >> 8) & 0xFF));
  payload.push_back(static_cast<std::uint8_t>(ssrc & 0xFF));

  return payload;
}

void apply_entropy_normalization(std::vector<std::uint8_t>& buffer,
                                  const std::array<std::uint8_t, kProfileSeedSize>& seed,
                                  std::uint64_t sequence) {
  // Count byte frequency.
  std::array<std::size_t, 256> frequency{};
  for (const auto byte : buffer) {
    ++frequency[byte];
  }

  // Find underrepresented bytes (appear less than expected).
  const auto expected_count = buffer.size() / 256;
  std::vector<std::uint8_t> underrepresented;
  for (std::size_t i = 0; i < 256; ++i) {
    if (frequency[i] < expected_count) {
      underrepresented.push_back(static_cast<std::uint8_t>(i));
    }
  }

  if (underrepresented.empty()) {
    return;  // Already normalized enough.
  }

  // Generate deterministic substitution pattern.
  std::vector<std::uint8_t> input;
  input.reserve(seed.size() + 8 + 7);
  input.insert(input.end(), seed.begin(), seed.end());
  for (int i = 7; i >= 0; --i) {
    input.push_back(static_cast<std::uint8_t>((sequence >> (8 * i)) & 0xFF));
  }
  const char* context = "entropy";
  input.insert(input.end(), context, context + 7);

  auto hmac = crypto::hmac_sha256(seed, input);

  // XOR some bytes to increase entropy (modifying padding bytes only).
  // This is a simplified approach - real implementation would be more sophisticated.
  const std::size_t bytes_to_modify = std::min(buffer.size() / 10, hmac.size());
  for (std::size_t i = 0; i < bytes_to_modify; ++i) {
    const auto idx = static_cast<std::size_t>(hmac[i]) % buffer.size();
    buffer[idx] ^= hmac[(i + 1) % hmac.size()];
  }
}

void update_metrics(ObfuscationMetrics& metrics, std::uint16_t packet_size,
                    std::uint16_t padding_size, std::uint16_t prefix_size,
                    double interval_ms, bool is_heartbeat) {
  ++metrics.packets_measured;

  // Update packet size statistics (Welford's online algorithm).
  const auto n = static_cast<double>(metrics.packets_measured);
  const auto delta = static_cast<double>(packet_size) - metrics.avg_packet_size;
  metrics.avg_packet_size += delta / n;
  const auto delta2 = static_cast<double>(packet_size) - metrics.avg_packet_size;
  metrics.packet_size_variance += delta * delta2;

  if (metrics.packets_measured > 1) {
    metrics.packet_size_stddev = std::sqrt(metrics.packet_size_variance / (n - 1.0));
  }

  // Update min/max.
  if (metrics.packets_measured == 1 || packet_size < metrics.min_packet_size) {
    metrics.min_packet_size = packet_size;
  }
  if (packet_size > metrics.max_packet_size) {
    metrics.max_packet_size = packet_size;
  }

  // Update size histogram.
  const auto bucket = std::min(static_cast<std::size_t>(packet_size / 64), std::size_t{15});
  ++metrics.size_histogram[bucket];

  // Update interval statistics.
  if (interval_ms >= 0.0) {
    const auto interval_delta = interval_ms - metrics.avg_interval_ms;
    metrics.avg_interval_ms += interval_delta / n;
    const auto interval_delta2 = interval_ms - metrics.avg_interval_ms;
    metrics.interval_variance += interval_delta * interval_delta2;

    if (metrics.packets_measured > 1) {
      metrics.interval_stddev = std::sqrt(metrics.interval_variance / (n - 1.0));
    }

    // Update timing histogram.
    const auto timing_bucket = std::min(static_cast<std::size_t>(interval_ms / 10.0), std::size_t{15});
    ++metrics.timing_histogram[timing_bucket];
  }

  // Update heartbeat statistics.
  if (is_heartbeat) {
    ++metrics.heartbeats_sent;
  }
  metrics.heartbeat_ratio = static_cast<double>(metrics.heartbeats_sent) / n;

  // Update padding statistics.
  metrics.total_padding_bytes += padding_size;
  metrics.avg_padding_per_packet = static_cast<double>(metrics.total_padding_bytes) / n;

  // Update padding size class distribution (based on size).
  if (padding_size <= 100) {
    ++metrics.small_padding_count;
  } else if (padding_size <= 400) {
    ++metrics.medium_padding_count;
  } else {
    ++metrics.large_padding_count;
  }

  // Update prefix statistics.
  metrics.total_prefix_bytes += prefix_size;
  metrics.avg_prefix_per_packet = static_cast<double>(metrics.total_prefix_bytes) / n;
}

void reset_metrics(ObfuscationMetrics& metrics) {
  metrics = ObfuscationMetrics{};
}

// ============================================================================
// DPI Bypass Mode Factory Functions
// ============================================================================

ObfuscationProfile create_dpi_mode_profile(DPIBypassMode mode) {
  using namespace std::chrono_literals;

  switch (mode) {
    case DPIBypassMode::kIoTMimic: {
      // Mode A: IoT Mimic - Simulate IoT sensor telemetry
      ObfuscationProfile profile;
      profile.enabled = true;
      profile.max_padding_size = 200;
      profile.min_padding_size = 20;
      profile.min_prefix_size = 4;
      profile.max_prefix_size = 8;
      profile.heartbeat_min = 10s;
      profile.heartbeat_max = 20s;
      profile.timing_jitter_enabled = true;
      profile.max_timing_jitter_ms = 30;
      profile.size_variance = 0.3f;
      profile.padding_distribution = {
          .small_weight = 70,  // Predominantly small packets
          .medium_weight = 25,
          .large_weight = 5,
          .small_min = 20,
          .small_max = 150,
          .medium_min = 150,
          .medium_max = 300,
          .large_min = 300,
          .large_max = 500,
          .jitter_range = 15,
      };
      profile.use_advanced_padding = true;
      profile.timing_jitter_model = TimingJitterModel::kPoisson;
      profile.timing_jitter_scale = 0.8f;
      profile.heartbeat_type = HeartbeatType::kIoTSensor;
      profile.heartbeat_timing_model = HeartbeatTimingModel::kExponential;  // Non-periodic timing
      profile.exponential_mean_seconds = 15.0f;
      profile.exponential_max_gap = 60s;
      profile.exponential_long_gap_probability = 0.15f;
      profile.heartbeat_entropy_normalization = true;
      return profile;
    }

    case DPIBypassMode::kQUICLike: {
      // Mode B: QUIC-Like - Mimic QUIC/HTTP3 traffic
      // NOW WITH WebSocket protocol wrapper for real protocol headers!
      ObfuscationProfile profile;
      profile.enabled = true;
      profile.max_padding_size = 1200;
      profile.min_padding_size = 100;
      profile.min_prefix_size = 8;
      profile.max_prefix_size = 16;
      profile.heartbeat_min = 30s;
      profile.heartbeat_max = 60s;
      profile.timing_jitter_enabled = true;
      profile.max_timing_jitter_ms = 100;
      profile.size_variance = 0.7f;
      profile.padding_distribution = {
          .small_weight = 20,
          .medium_weight = 30,
          .large_weight = 50,  // Predominantly large packets
          .small_min = 100,
          .small_max = 300,
          .medium_min = 300,
          .medium_max = 800,
          .large_min = 800,
          .large_max = 1200,
          .jitter_range = 50,
      };
      profile.use_advanced_padding = true;
      profile.timing_jitter_model = TimingJitterModel::kExponential;  // Bursty timing
      profile.timing_jitter_scale = 1.5f;
      profile.heartbeat_type = HeartbeatType::kRandomSize;  // Varied payload sizes
      profile.heartbeat_timing_model = HeartbeatTimingModel::kExponential;
      profile.exponential_mean_seconds = 45.0f;
      profile.exponential_max_gap = 180s;
      profile.exponential_long_gap_probability = 0.2f;
      profile.heartbeat_entropy_normalization = true;
      // Enable WebSocket wrapper for real protocol headers
      profile.protocol_wrapper = ProtocolWrapperType::kWebSocket;
      profile.is_client_to_server = true;
      return profile;
    }

    case DPIBypassMode::kRandomNoise: {
      // Mode C: Random-Noise Stealth - Maximum unpredictability
      ObfuscationProfile profile;
      profile.enabled = true;
      profile.max_padding_size = 1000;
      profile.min_padding_size = 0;
      profile.min_prefix_size = 4;
      profile.max_prefix_size = 20;
      profile.heartbeat_min = 60s;  // Infrequent heartbeats
      profile.heartbeat_max = 180s;
      profile.timing_jitter_enabled = true;
      profile.max_timing_jitter_ms = 500;  // Extreme jitter
      profile.size_variance = 1.0f;        // Maximum variance
      profile.padding_distribution = {
          .small_weight = 33,  // Equal distribution
          .medium_weight = 33,
          .large_weight = 34,
          .small_min = 0,
          .small_max = 333,
          .medium_min = 333,
          .medium_max = 666,
          .large_min = 666,
          .large_max = 1000,
          .jitter_range = 100,
      };
      profile.use_advanced_padding = true;
      profile.timing_jitter_model = TimingJitterModel::kUniform;  // Random timing
      profile.timing_jitter_scale = 2.0f;                         // Maximum jitter scale
      profile.heartbeat_type = HeartbeatType::kRandomSize;        // Varied payload sizes
      profile.heartbeat_timing_model = HeartbeatTimingModel::kBurst;  // Burst mode for unpredictability
      profile.burst_heartbeat_count_min = 2;
      profile.burst_heartbeat_count_max = 4;
      profile.burst_silence_min = 90s;
      profile.burst_silence_max = 240s;
      profile.burst_interval = 500ms;
      profile.heartbeat_entropy_normalization = true;
      return profile;
    }

    case DPIBypassMode::kTrickle: {
      // Mode D: Trickle Mode - Low-and-slow traffic
      ObfuscationProfile profile;
      profile.enabled = true;
      profile.max_padding_size = 100;
      profile.min_padding_size = 10;
      profile.min_prefix_size = 4;
      profile.max_prefix_size = 6;
      profile.heartbeat_min = 120s;  // Very infrequent heartbeats
      profile.heartbeat_max = 300s;
      profile.timing_jitter_enabled = true;
      profile.max_timing_jitter_ms = 500;  // High jitter for stealth
      profile.size_variance = 0.2f;        // Low variance (consistent small packets)
      profile.padding_distribution = {
          .small_weight = 100,  // Only small packets
          .medium_weight = 0,
          .large_weight = 0,
          .small_min = 10,
          .small_max = 100,
          .medium_min = 0,
          .medium_max = 0,
          .large_min = 0,
          .large_max = 0,
          .jitter_range = 10,
      };
      profile.use_advanced_padding = true;
      profile.timing_jitter_model = TimingJitterModel::kPoisson;
      profile.timing_jitter_scale = 1.2f;
      profile.heartbeat_type = HeartbeatType::kMimicDNS;  // DNS-like heartbeats (common background traffic)
      profile.heartbeat_timing_model = HeartbeatTimingModel::kExponential;
      profile.exponential_mean_seconds = 180.0f;  // Very infrequent
      profile.exponential_max_gap = 600s;  // Up to 10 minutes
      profile.exponential_long_gap_probability = 0.3f;
      profile.heartbeat_entropy_normalization = false;     // Low entropy for IoT-like traffic
      return profile;
    }

    case DPIBypassMode::kCustom:
    default:
      // Return default profile
      return ObfuscationProfile{};
  }
}

const char* dpi_mode_to_string(DPIBypassMode mode) {
  switch (mode) {
    case DPIBypassMode::kIoTMimic:
      return "IoT Mimic";
    case DPIBypassMode::kQUICLike:
      return "QUIC-Like";
    case DPIBypassMode::kRandomNoise:
      return "Random-Noise Stealth";
    case DPIBypassMode::kTrickle:
      return "Trickle Mode";
    case DPIBypassMode::kCustom:
      return "Custom";
    default:
      return "Unknown";
  }
}

std::optional<DPIBypassMode> dpi_mode_from_string(const std::string& str) {
  if (str == "IoT Mimic" || str == "iot_mimic" || str == "0") {
    return DPIBypassMode::kIoTMimic;
  }
  if (str == "QUIC-Like" || str == "quic_like" || str == "1") {
    return DPIBypassMode::kQUICLike;
  }
  if (str == "Random-Noise Stealth" || str == "random_noise" || str == "2") {
    return DPIBypassMode::kRandomNoise;
  }
  if (str == "Trickle Mode" || str == "trickle" || str == "3") {
    return DPIBypassMode::kTrickle;
  }
  if (str == "Custom" || str == "custom" || str == "255") {
    return DPIBypassMode::kCustom;
  }
  return std::nullopt;
}

const char* dpi_mode_description(DPIBypassMode mode) {
  switch (mode) {
    case DPIBypassMode::kIoTMimic:
      return "Simulates IoT sensor traffic. Good balance of stealth and performance.";
    case DPIBypassMode::kQUICLike:
      return "Mimics WebSocket traffic with real protocol headers. Best for high-throughput scenarios.";
    case DPIBypassMode::kRandomNoise:
      return "Maximum unpredictability. Use in extreme censorship scenarios.";
    case DPIBypassMode::kTrickle:
      return "Low-and-slow traffic. Maximum stealth but limited bandwidth (10-50 kbit/s).";
    case DPIBypassMode::kCustom:
      return "User-defined custom profile.";
    default:
      return "Unknown mode.";
  }
}

const char* protocol_wrapper_to_string(ProtocolWrapperType wrapper) {
  switch (wrapper) {
    case ProtocolWrapperType::kNone:
      return "None";
    case ProtocolWrapperType::kWebSocket:
      return "WebSocket";
    default:
      return "Unknown";
  }
}

std::optional<ProtocolWrapperType> protocol_wrapper_from_string(const std::string& str) {
  if (str == "None" || str == "none" || str == "0") {
    return ProtocolWrapperType::kNone;
  }
  if (str == "WebSocket" || str == "websocket" || str == "1") {
    return ProtocolWrapperType::kWebSocket;
  }
  return std::nullopt;
}

}  // namespace veil::obfuscation
