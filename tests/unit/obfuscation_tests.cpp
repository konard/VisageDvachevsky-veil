#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <set>
#include <vector>

#include "common/obfuscation/obfuscation_profile.h"

namespace veil::obfuscation::tests {

class ObfuscationProfileTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Create a deterministic profile for testing.
    profile_.enabled = true;
    profile_.min_padding_size = 10;
    profile_.max_padding_size = 100;
    profile_.min_prefix_size = 4;
    profile_.max_prefix_size = 12;
    profile_.heartbeat_min = std::chrono::seconds(5);
    profile_.heartbeat_max = std::chrono::seconds(15);
    profile_.timing_jitter_enabled = true;
    profile_.max_timing_jitter_ms = 50;

    // Set deterministic seed.
    for (std::size_t i = 0; i < profile_.profile_seed.size(); ++i) {
      profile_.profile_seed[i] = static_cast<std::uint8_t>(i);
    }
  }

  ObfuscationProfile profile_;
};

TEST_F(ObfuscationProfileTest, GenerateProfileSeedIsRandom) {
  auto seed1 = generate_profile_seed();
  auto seed2 = generate_profile_seed();

  // Seeds should be different (with overwhelming probability).
  EXPECT_NE(seed1, seed2);

  // Seeds should not be all zeros.
  bool all_zero1 = std::all_of(seed1.begin(), seed1.end(), [](uint8_t b) { return b == 0; });
  bool all_zero2 = std::all_of(seed2.begin(), seed2.end(), [](uint8_t b) { return b == 0; });
  EXPECT_FALSE(all_zero1);
  EXPECT_FALSE(all_zero2);
}

TEST_F(ObfuscationProfileTest, ComputePaddingSizeWithinBounds) {
  for (std::uint64_t seq = 0; seq < 1000; ++seq) {
    auto size = compute_padding_size(profile_, seq);
    EXPECT_GE(size, profile_.min_padding_size);
    EXPECT_LE(size, profile_.max_padding_size);
  }
}

TEST_F(ObfuscationProfileTest, ComputePaddingSizeIsDeterministic) {
  for (std::uint64_t seq = 0; seq < 100; ++seq) {
    auto size1 = compute_padding_size(profile_, seq);
    auto size2 = compute_padding_size(profile_, seq);
    EXPECT_EQ(size1, size2);
  }
}

TEST_F(ObfuscationProfileTest, ComputePaddingSizeVariesWithSequence) {
  std::set<std::uint16_t> sizes;
  for (std::uint64_t seq = 0; seq < 1000; ++seq) {
    sizes.insert(compute_padding_size(profile_, seq));
  }
  // Should have good variance (at least 10 different sizes).
  EXPECT_GE(sizes.size(), 10U);
}

TEST_F(ObfuscationProfileTest, ComputePaddingSizeDisabledReturnsZero) {
  profile_.enabled = false;
  EXPECT_EQ(compute_padding_size(profile_, 0), 0U);
  EXPECT_EQ(compute_padding_size(profile_, 100), 0U);
}

TEST_F(ObfuscationProfileTest, ComputePaddingSizeZeroMaxReturnsZero) {
  profile_.max_padding_size = 0;
  EXPECT_EQ(compute_padding_size(profile_, 0), 0U);
}

TEST_F(ObfuscationProfileTest, ComputePrefixSizeWithinBounds) {
  for (std::uint64_t seq = 0; seq < 1000; ++seq) {
    auto size = compute_prefix_size(profile_, seq);
    EXPECT_GE(size, profile_.min_prefix_size);
    EXPECT_LE(size, profile_.max_prefix_size);
  }
}

TEST_F(ObfuscationProfileTest, ComputePrefixSizeIsDeterministic) {
  for (std::uint64_t seq = 0; seq < 100; ++seq) {
    auto size1 = compute_prefix_size(profile_, seq);
    auto size2 = compute_prefix_size(profile_, seq);
    EXPECT_EQ(size1, size2);
  }
}

TEST_F(ObfuscationProfileTest, ComputePrefixSizeDisabledReturnsZero) {
  profile_.enabled = false;
  EXPECT_EQ(compute_prefix_size(profile_, 0), 0U);
}

TEST_F(ObfuscationProfileTest, ComputeTimingJitterWithinBounds) {
  for (std::uint64_t seq = 0; seq < 1000; ++seq) {
    auto jitter = compute_timing_jitter(profile_, seq);
    EXPECT_LE(jitter, profile_.max_timing_jitter_ms);
  }
}

TEST_F(ObfuscationProfileTest, ComputeTimingJitterDisabled) {
  profile_.timing_jitter_enabled = false;
  EXPECT_EQ(compute_timing_jitter(profile_, 0), 0U);
  EXPECT_EQ(compute_timing_jitter(profile_, 100), 0U);
}

TEST_F(ObfuscationProfileTest, ComputeHeartbeatIntervalWithinBounds) {
  auto min_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(profile_.heartbeat_min).count();
  auto max_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(profile_.heartbeat_max).count();

  for (std::uint64_t count = 0; count < 1000; ++count) {
    auto interval = compute_heartbeat_interval(profile_, count);
    EXPECT_GE(interval.count(), min_ms);
    EXPECT_LE(interval.count(), max_ms);
  }
}

TEST_F(ObfuscationProfileTest, ComputeHeartbeatIntervalIsDeterministic) {
  for (std::uint64_t count = 0; count < 100; ++count) {
    auto interval1 = compute_heartbeat_interval(profile_, count);
    auto interval2 = compute_heartbeat_interval(profile_, count);
    EXPECT_EQ(interval1, interval2);
  }
}

TEST_F(ObfuscationProfileTest, ConfigToProfileWithAutoSeed) {
  ObfuscationConfig config;
  config.enabled = true;
  config.max_padding_size = 200;
  config.profile_seed_hex = "auto";
  config.heartbeat_interval_min = std::chrono::seconds(10);
  config.heartbeat_interval_max = std::chrono::seconds(30);
  config.enable_timing_jitter = false;

  auto profile = config_to_profile(config);

  EXPECT_TRUE(profile.enabled);
  EXPECT_EQ(profile.max_padding_size, 200U);
  EXPECT_EQ(profile.heartbeat_min, std::chrono::seconds(10));
  EXPECT_EQ(profile.heartbeat_max, std::chrono::seconds(30));
  EXPECT_FALSE(profile.timing_jitter_enabled);

  // Seed should be generated (not all zeros).
  bool all_zero =
      std::all_of(profile.profile_seed.begin(), profile.profile_seed.end(),
                  [](uint8_t b) { return b == 0; });
  EXPECT_FALSE(all_zero);
}

TEST_F(ObfuscationProfileTest, ConfigToProfileWithHexSeed) {
  ObfuscationConfig config;
  config.enabled = true;
  config.max_padding_size = 100;
  // 32-byte seed in hex (64 hex chars).
  config.profile_seed_hex =
      "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20";
  config.heartbeat_interval_min = std::chrono::seconds(5);
  config.heartbeat_interval_max = std::chrono::seconds(15);
  config.enable_timing_jitter = true;

  auto profile = config_to_profile(config);

  EXPECT_TRUE(profile.enabled);

  // Check seed was parsed correctly.
  EXPECT_EQ(profile.profile_seed[0], 0x01);
  EXPECT_EQ(profile.profile_seed[1], 0x02);
  EXPECT_EQ(profile.profile_seed[31], 0x20);
}

TEST_F(ObfuscationProfileTest, ParseObfuscationConfig) {
  auto config = parse_obfuscation_config("true", "500", "auto", "10", "30", "true");

  ASSERT_TRUE(config.has_value());
  EXPECT_TRUE(config->enabled);
  EXPECT_EQ(config->max_padding_size, 500U);
  EXPECT_EQ(config->profile_seed_hex, "auto");
  EXPECT_EQ(config->heartbeat_interval_min, std::chrono::seconds(10));
  EXPECT_EQ(config->heartbeat_interval_max, std::chrono::seconds(30));
  EXPECT_TRUE(config->enable_timing_jitter);
}

TEST_F(ObfuscationProfileTest, ParseObfuscationConfigDisabled) {
  auto config = parse_obfuscation_config("false", "100", "auto", "5", "15", "false");

  ASSERT_TRUE(config.has_value());
  EXPECT_FALSE(config->enabled);
  EXPECT_FALSE(config->enable_timing_jitter);
}

TEST_F(ObfuscationProfileTest, DifferentSeedsProduceDifferentResults) {
  ObfuscationProfile profile2 = profile_;
  // Change the seed.
  profile2.profile_seed[0] = 0xFF;

  // Results should differ for same sequence.
  EXPECT_NE(compute_padding_size(profile_, 0), compute_padding_size(profile2, 0));
  EXPECT_NE(compute_prefix_size(profile_, 0), compute_prefix_size(profile2, 0));
}

// ========== Stage 4: Advanced padding distribution tests ==========

TEST_F(ObfuscationProfileTest, AdvancedPaddingDistributionClasses) {
  // Enable advanced padding.
  profile_.use_advanced_padding = true;
  profile_.padding_distribution.small_weight = 40;
  profile_.padding_distribution.medium_weight = 40;
  profile_.padding_distribution.large_weight = 20;

  // Count class distribution over many samples.
  std::uint32_t small_count = 0;
  std::uint32_t medium_count = 0;
  std::uint32_t large_count = 0;

  for (std::uint64_t seq = 0; seq < 10000; ++seq) {
    auto padding_class = compute_padding_class(profile_, seq);
    switch (padding_class) {
      case PaddingSizeClass::kSmall:
        ++small_count;
        break;
      case PaddingSizeClass::kMedium:
        ++medium_count;
        break;
      case PaddingSizeClass::kLarge:
        ++large_count;
        break;
    }
  }

  // Should roughly match configured weights (with some tolerance).
  // Expected: 40% small, 40% medium, 20% large.
  EXPECT_GT(small_count, 3000U);   // At least 30%
  EXPECT_LT(small_count, 5000U);   // At most 50%
  EXPECT_GT(medium_count, 3000U);
  EXPECT_LT(medium_count, 5000U);
  EXPECT_GT(large_count, 1000U);   // At least 10%
  EXPECT_LT(large_count, 3000U);   // At most 30%
}

TEST_F(ObfuscationProfileTest, AdvancedPaddingSizeWithinClassBounds) {
  profile_.use_advanced_padding = true;
  profile_.padding_distribution.small_min = 10;
  profile_.padding_distribution.small_max = 50;
  profile_.padding_distribution.medium_min = 100;
  profile_.padding_distribution.medium_max = 200;
  profile_.padding_distribution.large_min = 300;
  profile_.padding_distribution.large_max = 500;
  profile_.padding_distribution.jitter_range = 0;  // Disable jitter for this test.

  for (std::uint64_t seq = 0; seq < 1000; ++seq) {
    auto size = compute_advanced_padding_size(profile_, seq);
    auto padding_class = compute_padding_class(profile_, seq);

    switch (padding_class) {
      case PaddingSizeClass::kSmall:
        EXPECT_GE(size, 10U);
        EXPECT_LE(size, 50U);
        break;
      case PaddingSizeClass::kMedium:
        EXPECT_GE(size, 100U);
        EXPECT_LE(size, 200U);
        break;
      case PaddingSizeClass::kLarge:
        EXPECT_GE(size, 300U);
        EXPECT_LE(size, 500U);
        break;
    }
  }
}

// ========== Stage 4: Timing jitter model tests ==========

TEST_F(ObfuscationProfileTest, TimingJitterAdvancedUniform) {
  profile_.timing_jitter_model = TimingJitterModel::kUniform;
  profile_.max_timing_jitter_ms = 100;
  profile_.timing_jitter_scale = 1.0f;

  std::uint64_t total_jitter = 0;
  for (std::uint64_t seq = 0; seq < 1000; ++seq) {
    auto jitter = compute_timing_jitter_advanced(profile_, seq);
    EXPECT_GE(jitter.count(), 0);
    EXPECT_LE(jitter.count(), 100000);  // 100ms in microseconds
    total_jitter += static_cast<std::uint64_t>(jitter.count());
  }

  // Mean should be around 50ms (half of max) for uniform.
  auto mean_us = total_jitter / 1000;
  EXPECT_GT(mean_us, 30000U);  // At least 30ms
  EXPECT_LT(mean_us, 70000U);  // At most 70ms
}

TEST_F(ObfuscationProfileTest, TimingJitterAdvancedPoisson) {
  profile_.timing_jitter_model = TimingJitterModel::kPoisson;
  profile_.max_timing_jitter_ms = 100;
  profile_.timing_jitter_scale = 1.0f;

  for (std::uint64_t seq = 0; seq < 1000; ++seq) {
    auto jitter = compute_timing_jitter_advanced(profile_, seq);
    EXPECT_GE(jitter.count(), 0);
    EXPECT_LE(jitter.count(), 100000);  // Capped at max
  }
}

TEST_F(ObfuscationProfileTest, TimingJitterAdvancedExponential) {
  profile_.timing_jitter_model = TimingJitterModel::kExponential;
  profile_.max_timing_jitter_ms = 100;
  profile_.timing_jitter_scale = 1.0f;

  for (std::uint64_t seq = 0; seq < 1000; ++seq) {
    auto jitter = compute_timing_jitter_advanced(profile_, seq);
    EXPECT_GE(jitter.count(), 0);
    EXPECT_LE(jitter.count(), 100000);  // Capped at max
  }
}

TEST_F(ObfuscationProfileTest, CalculateNextSendTs) {
  profile_.timing_jitter_enabled = true;
  profile_.max_timing_jitter_ms = 50;

  auto base_ts = std::chrono::steady_clock::now();
  auto adjusted_ts = calculate_next_send_ts(profile_, 0, base_ts);

  // Adjusted timestamp should be >= base (jitter adds delay).
  EXPECT_GE(adjusted_ts, base_ts);
  EXPECT_LE(adjusted_ts - base_ts, std::chrono::milliseconds(50));
}

// ========== Stage 4: Heartbeat payload tests ==========

TEST_F(ObfuscationProfileTest, GenerateIoTHeartbeatPayload) {
  profile_.heartbeat_type = HeartbeatType::kIoTSensor;

  auto payload1 = generate_iot_heartbeat_payload(profile_, 0);
  auto payload2 = generate_iot_heartbeat_payload(profile_, 0);
  auto payload3 = generate_iot_heartbeat_payload(profile_, 1);

  // Same sequence should produce same payload.
  EXPECT_EQ(payload1, payload2);

  // Different sequences should produce different payloads.
  EXPECT_NE(payload1, payload3);

  // Payload should have expected structure (24 bytes).
  EXPECT_EQ(payload1.size(), 24U);

  // First byte should be message type (0x01).
  EXPECT_EQ(payload1[0], 0x01);
}

TEST_F(ObfuscationProfileTest, GenerateTelemetryHeartbeatPayload) {
  profile_.heartbeat_type = HeartbeatType::kGenericTelemetry;

  auto payload = generate_telemetry_heartbeat_payload(profile_, 0);

  // Payload should have expected structure (24 bytes).
  EXPECT_EQ(payload.size(), 24U);

  // First 4 bytes should be magic "TELM".
  EXPECT_EQ(payload[0], 0x54);  // 'T'
  EXPECT_EQ(payload[1], 0x45);  // 'E'
  EXPECT_EQ(payload[2], 0x4C);  // 'L'
  EXPECT_EQ(payload[3], 0x4D);  // 'M'
}

TEST_F(ObfuscationProfileTest, GenerateHeartbeatPayloadByType) {
  // Empty heartbeat.
  profile_.heartbeat_type = HeartbeatType::kEmpty;
  auto empty_payload = generate_heartbeat_payload(profile_, 0);
  EXPECT_TRUE(empty_payload.empty());

  // Timestamp heartbeat.
  profile_.heartbeat_type = HeartbeatType::kTimestamp;
  auto ts_payload = generate_heartbeat_payload(profile_, 0);
  EXPECT_EQ(ts_payload.size(), 8U);

  // IoT sensor heartbeat.
  profile_.heartbeat_type = HeartbeatType::kIoTSensor;
  auto iot_payload = generate_heartbeat_payload(profile_, 0);
  EXPECT_EQ(iot_payload.size(), 24U);

  // Generic telemetry heartbeat.
  profile_.heartbeat_type = HeartbeatType::kGenericTelemetry;
  auto telemetry_payload = generate_heartbeat_payload(profile_, 0);
  EXPECT_EQ(telemetry_payload.size(), 24U);
}

// ========== Stage 4: Metrics tests ==========

TEST_F(ObfuscationProfileTest, UpdateMetrics) {
  ObfuscationMetrics metrics{};

  update_metrics(metrics, 100, 20, 8, 10.0, false);
  EXPECT_EQ(metrics.packets_measured, 1U);
  EXPECT_DOUBLE_EQ(metrics.avg_packet_size, 100.0);
  EXPECT_EQ(metrics.min_packet_size, 100U);
  EXPECT_EQ(metrics.max_packet_size, 100U);

  update_metrics(metrics, 200, 40, 12, 20.0, true);
  EXPECT_EQ(metrics.packets_measured, 2U);
  EXPECT_DOUBLE_EQ(metrics.avg_packet_size, 150.0);
  EXPECT_EQ(metrics.min_packet_size, 100U);
  EXPECT_EQ(metrics.max_packet_size, 200U);
  EXPECT_EQ(metrics.heartbeats_sent, 1U);
}

TEST_F(ObfuscationProfileTest, ResetMetrics) {
  ObfuscationMetrics metrics{};
  metrics.packets_measured = 100;
  metrics.avg_packet_size = 150.0;

  reset_metrics(metrics);

  EXPECT_EQ(metrics.packets_measured, 0U);
  EXPECT_DOUBLE_EQ(metrics.avg_packet_size, 0.0);
}

// ========== Heartbeat Timing Model Tests ==========

TEST_F(ObfuscationProfileTest, HeartbeatTimingUniformModel) {
  profile_.heartbeat_timing_model = HeartbeatTimingModel::kUniform;
  profile_.heartbeat_min = std::chrono::seconds(5);
  profile_.heartbeat_max = std::chrono::seconds(15);

  auto min_ms = std::chrono::duration_cast<std::chrono::milliseconds>(profile_.heartbeat_min).count();
  auto max_ms = std::chrono::duration_cast<std::chrono::milliseconds>(profile_.heartbeat_max).count();

  // Test that intervals are within bounds.
  for (std::uint64_t count = 0; count < 1000; ++count) {
    auto interval = compute_heartbeat_interval(profile_, count);
    EXPECT_GE(interval.count(), min_ms);
    EXPECT_LE(interval.count(), max_ms);
  }
}

TEST_F(ObfuscationProfileTest, HeartbeatTimingExponentialModel) {
  profile_.heartbeat_timing_model = HeartbeatTimingModel::kExponential;
  profile_.exponential_mean_seconds = 10.0f;
  profile_.exponential_max_gap = std::chrono::seconds(60);
  profile_.exponential_long_gap_probability = 0.1f;

  std::uint64_t long_gap_count = 0;
  std::uint64_t total_count = 1000;

  // Test that exponential intervals are non-periodic.
  for (std::uint64_t count = 0; count < total_count; ++count) {
    auto interval = compute_heartbeat_interval_exponential(profile_, count);

    // Should be at least 1 second.
    EXPECT_GE(interval.count(), 1000);

    // Should not exceed max gap.
    EXPECT_LE(interval.count(), 60000);

    // Count long gaps (> 30 seconds).
    if (interval.count() > 30000) {
      ++long_gap_count;
    }
  }

  // Should have some long gaps (roughly 10% based on probability).
  // Allow tolerance: 5-20%.
  EXPECT_GT(long_gap_count, 30U);   // At least 3%
  EXPECT_LT(long_gap_count, 300U);  // At most 30%
}

TEST_F(ObfuscationProfileTest, HeartbeatTimingBurstModel) {
  profile_.heartbeat_timing_model = HeartbeatTimingModel::kBurst;
  profile_.burst_heartbeat_count_min = 3;
  profile_.burst_heartbeat_count_max = 5;
  profile_.burst_silence_min = std::chrono::seconds(30);
  profile_.burst_silence_max = std::chrono::seconds(60);
  profile_.burst_interval = std::chrono::milliseconds(200);

  // Test burst pattern over one cycle.
  bool is_burst_start = false;
  std::vector<std::chrono::milliseconds> intervals;

  for (std::uint64_t count = 0; count < 20; ++count) {
    auto interval = compute_heartbeat_interval_burst(profile_, count, is_burst_start);
    intervals.push_back(interval);
  }

  // Should have mix of short (burst) and long (silence) intervals.
  bool has_short = false;
  bool has_long = false;

  for (const auto& interval : intervals) {
    if (interval.count() < 1000) {  // Less than 1 second = burst interval
      has_short = true;
    }
    if (interval.count() > 10000) {  // More than 10 seconds = silence interval
      has_long = true;
    }
  }

  EXPECT_TRUE(has_short);
  EXPECT_TRUE(has_long);
}

TEST_F(ObfuscationProfileTest, HeartbeatTimingModelsDeterministic) {
  // Test that timing models produce deterministic results.
  profile_.heartbeat_timing_model = HeartbeatTimingModel::kExponential;

  for (std::uint64_t count = 0; count < 100; ++count) {
    auto interval1 = compute_heartbeat_interval(profile_, count);
    auto interval2 = compute_heartbeat_interval(profile_, count);
    EXPECT_EQ(interval1, interval2);
  }
}

// ========== New Heartbeat Payload Type Tests ==========

TEST_F(ObfuscationProfileTest, GenerateRandomSizeHeartbeatPayload) {
  profile_.heartbeat_type = HeartbeatType::kRandomSize;

  auto payload1 = generate_random_size_heartbeat_payload(profile_, 0);
  auto payload2 = generate_random_size_heartbeat_payload(profile_, 1);

  // Payloads should be between 8 and 200 bytes.
  EXPECT_GE(payload1.size(), 8U);
  EXPECT_LE(payload1.size(), 200U);
  EXPECT_GE(payload2.size(), 8U);
  EXPECT_LE(payload2.size(), 200U);

  // Different sequences should produce different payloads.
  EXPECT_NE(payload1, payload2);

  // Same sequence should produce same payload.
  auto payload1_again = generate_random_size_heartbeat_payload(profile_, 0);
  EXPECT_EQ(payload1, payload1_again);
}

TEST_F(ObfuscationProfileTest, GenerateDNSMimicHeartbeatPayload) {
  profile_.heartbeat_type = HeartbeatType::kMimicDNS;

  auto payload = generate_dns_mimic_heartbeat_payload(profile_, 0);

  // DNS response should be at least 12 bytes (header) + question + answer.
  EXPECT_GT(payload.size(), 12U);

  // Check DNS header flags (offset 2-3).
  // Should have QR=1 (response), RCODE=0 (no error).
  EXPECT_EQ(payload[2] & 0x80, 0x80);  // QR bit set
  EXPECT_EQ(payload[3] & 0x0F, 0x00);  // RCODE = 0

  // Check QDCOUNT (offset 4-5): should be 1 question.
  EXPECT_EQ(payload[4], 0x00);
  EXPECT_EQ(payload[5], 0x01);

  // Check ANCOUNT (offset 6-7): should be 1 answer.
  EXPECT_EQ(payload[6], 0x00);
  EXPECT_EQ(payload[7], 0x01);
}

TEST_F(ObfuscationProfileTest, GenerateSTUNMimicHeartbeatPayload) {
  profile_.heartbeat_type = HeartbeatType::kMimicSTUN;

  auto payload = generate_stun_mimic_heartbeat_payload(profile_, 0);

  // STUN message should have 20-byte header + attributes.
  EXPECT_GE(payload.size(), 20U);

  // Check message type (offset 0-1): should be 0x0101 (Binding Response Success).
  EXPECT_EQ(payload[0], 0x01);
  EXPECT_EQ(payload[1], 0x01);

  // Check magic cookie (offset 4-7): should be 0x2112A442.
  EXPECT_EQ(payload[4], 0x21);
  EXPECT_EQ(payload[5], 0x12);
  EXPECT_EQ(payload[6], 0xA4);
  EXPECT_EQ(payload[7], 0x42);
}

TEST_F(ObfuscationProfileTest, GenerateRTPMimicHeartbeatPayload) {
  profile_.heartbeat_type = HeartbeatType::kMimicRTP;

  auto payload = generate_rtp_mimic_heartbeat_payload(profile_, 0);

  // RTP header should be exactly 12 bytes.
  EXPECT_EQ(payload.size(), 12U);

  // Check version (offset 0, bits 6-7): should be 2.
  EXPECT_EQ((payload[0] >> 6) & 0x03, 2);

  // Check payload type (offset 1, bits 0-6): should be 96.
  EXPECT_EQ(payload[1] & 0x7F, 96);
}

TEST_F(ObfuscationProfileTest, GenerateHeartbeatPayloadByNewTypes) {
  // Test that generate_heartbeat_payload dispatches correctly to new types.

  profile_.heartbeat_type = HeartbeatType::kRandomSize;
  auto random_payload = generate_heartbeat_payload(profile_, 0);
  EXPECT_GE(random_payload.size(), 8U);
  EXPECT_LE(random_payload.size(), 200U);

  profile_.heartbeat_type = HeartbeatType::kMimicDNS;
  auto dns_payload = generate_heartbeat_payload(profile_, 0);
  EXPECT_GT(dns_payload.size(), 12U);

  profile_.heartbeat_type = HeartbeatType::kMimicSTUN;
  auto stun_payload = generate_heartbeat_payload(profile_, 0);
  EXPECT_GE(stun_payload.size(), 20U);

  profile_.heartbeat_type = HeartbeatType::kMimicRTP;
  auto rtp_payload = generate_heartbeat_payload(profile_, 0);
  EXPECT_EQ(rtp_payload.size(), 12U);
}

TEST_F(ObfuscationProfileTest, HeartbeatPayloadVarianceAcrossSequences) {
  // Test that payloads vary across different sequences (non-predictable).
  profile_.heartbeat_type = HeartbeatType::kRandomSize;

  std::set<std::size_t> sizes;
  for (std::uint64_t seq = 0; seq < 100; ++seq) {
    auto payload = generate_heartbeat_payload(profile_, seq);
    sizes.insert(payload.size());
  }

  // Should have good variance in sizes (at least 20 different sizes).
  EXPECT_GE(sizes.size(), 20U);
}

// ========== DPI Mode Profile Tests for New Features ==========

TEST_F(ObfuscationProfileTest, DPIModeIoTMimicUsesExponentialTiming) {
  auto profile = create_dpi_mode_profile(DPIBypassMode::kIoTMimic);
  EXPECT_EQ(profile.heartbeat_timing_model, HeartbeatTimingModel::kExponential);
  EXPECT_GT(profile.exponential_mean_seconds, 0.0f);
}

TEST_F(ObfuscationProfileTest, DPIModeQUICLikeUsesVariedPayloads) {
  auto profile = create_dpi_mode_profile(DPIBypassMode::kQUICLike);
  EXPECT_EQ(profile.heartbeat_timing_model, HeartbeatTimingModel::kExponential);
  EXPECT_EQ(profile.heartbeat_type, HeartbeatType::kRandomSize);
}

TEST_F(ObfuscationProfileTest, DPIModeRandomNoiseUsesBurstMode) {
  auto profile = create_dpi_mode_profile(DPIBypassMode::kRandomNoise);
  EXPECT_EQ(profile.heartbeat_timing_model, HeartbeatTimingModel::kBurst);
  EXPECT_EQ(profile.heartbeat_type, HeartbeatType::kRandomSize);
  EXPECT_GT(profile.burst_heartbeat_count_min, 0);
  EXPECT_GT(profile.burst_heartbeat_count_max, 0);
}

TEST_F(ObfuscationProfileTest, DPIModeTrickleUsesDNSMimic) {
  auto profile = create_dpi_mode_profile(DPIBypassMode::kTrickle);
  EXPECT_EQ(profile.heartbeat_type, HeartbeatType::kMimicDNS);
  EXPECT_EQ(profile.heartbeat_timing_model, HeartbeatTimingModel::kExponential);
}

}  // namespace veil::obfuscation::tests
