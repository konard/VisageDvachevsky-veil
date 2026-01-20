#include <gtest/gtest.h>

#include <chrono>

#include "common/utils/advanced_rate_limiter.h"

namespace veil::utils::test {

class AdvancedRateLimiterTest : public ::testing::Test {
 protected:
  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;

  void SetUp() override { current_time_ = Clock::now(); }

  TimePoint now() { return current_time_; }

  void advance_time(std::chrono::milliseconds ms) { current_time_ += ms; }

  TimePoint current_time_;
};

// BurstTokenBucket tests.

TEST_F(AdvancedRateLimiterTest, BurstTokenBucket_AllowsWithinCapacity) {
  BurstTokenBucket bucket(1000, 1.5, std::chrono::milliseconds(1000), [this]() { return now(); });

  // Should allow tokens within capacity.
  EXPECT_TRUE(bucket.try_consume(100));
  EXPECT_TRUE(bucket.try_consume(100));
  EXPECT_TRUE(bucket.try_consume(100));
}

TEST_F(AdvancedRateLimiterTest, BurstTokenBucket_AllowsBurstAboveRate) {
  // Rate of 100/sec with 1.5x burst = 150 capacity.
  BurstTokenBucket bucket(100, 1.5, std::chrono::milliseconds(1000), [this]() { return now(); });

  // Should allow burst.
  EXPECT_TRUE(bucket.try_consume(140));
  EXPECT_LT(bucket.current_tokens(), 20.0);
}

TEST_F(AdvancedRateLimiterTest, BurstTokenBucket_RefillsOverTime) {
  // Use a short penalty duration so we can test refill without penalty interference.
  BurstTokenBucket bucket(1000, 1.0, std::chrono::milliseconds(100), [this]() { return now(); });

  // Consume all tokens.
  EXPECT_TRUE(bucket.try_consume(1000));
  EXPECT_FALSE(bucket.try_consume(100));  // Triggers penalty.

  // Advance 500ms (past penalty of 100ms) - should refill ~500 tokens.
  advance_time(std::chrono::milliseconds(500));
  EXPECT_TRUE(bucket.try_consume(400));
}

TEST_F(AdvancedRateLimiterTest, BurstTokenBucket_PenaltyPeriod) {
  BurstTokenBucket bucket(100, 1.0, std::chrono::milliseconds(500), [this]() { return now(); });

  // Exhaust tokens to trigger penalty.
  EXPECT_TRUE(bucket.try_consume(95));
  EXPECT_FALSE(bucket.try_consume(50));  // Should fail and trigger penalty.

  // Check penalty.
  EXPECT_TRUE(bucket.is_penalized());

  // Advance past penalty.
  advance_time(std::chrono::milliseconds(600));
  EXPECT_FALSE(bucket.is_penalized());
}

// ClientRateLimiter tests.

TEST_F(AdvancedRateLimiterTest, ClientRateLimiter_AllowsPackets) {
  RateLimiterConfig config;
  config.bandwidth_bytes_per_sec = 1000000;  // 1 MB/s
  config.packets_per_sec = 10000;

  ClientRateLimiter limiter(config, [this]() { return now(); });

  EXPECT_TRUE(limiter.allow_packet(1000, TrafficPriority::kNormal));
  EXPECT_TRUE(limiter.allow_packet(1000, TrafficPriority::kNormal));
}

TEST_F(AdvancedRateLimiterTest, ClientRateLimiter_CriticalAlwaysAllowed) {
  RateLimiterConfig config;
  config.bandwidth_bytes_per_sec = 100;  // Very low limit.
  config.packets_per_sec = 1;

  ClientRateLimiter limiter(config, [this]() { return now(); });

  // Exhaust normal quota.
  limiter.allow_packet(200, TrafficPriority::kNormal);

  // Critical should still be allowed.
  EXPECT_TRUE(limiter.allow_packet(1000, TrafficPriority::kCritical));
}

TEST_F(AdvancedRateLimiterTest, ClientRateLimiter_TracksStats) {
  RateLimiterConfig config;
  config.bandwidth_bytes_per_sec = 1000000;
  config.packets_per_sec = 10000;

  ClientRateLimiter limiter(config, [this]() { return now(); });

  limiter.allow_packet(1000, TrafficPriority::kNormal);
  limiter.allow_packet(2000, TrafficPriority::kNormal);

  EXPECT_EQ(limiter.stats().bytes_allowed, 3000u);
  EXPECT_EQ(limiter.stats().packets_allowed, 2u);
}

TEST_F(AdvancedRateLimiterTest, ClientRateLimiter_ReconnectLimit) {
  RateLimiterConfig config;
  config.max_reconnects_per_minute = 3;

  ClientRateLimiter limiter(config, [this]() { return now(); });

  EXPECT_TRUE(limiter.record_reconnect());
  EXPECT_TRUE(limiter.record_reconnect());
  EXPECT_TRUE(limiter.record_reconnect());
  EXPECT_FALSE(limiter.record_reconnect());  // 4th should fail.
}

TEST_F(AdvancedRateLimiterTest, ClientRateLimiter_ReconnectResetsAfterMinute) {
  RateLimiterConfig config;
  config.max_reconnects_per_minute = 2;

  ClientRateLimiter limiter(config, [this]() { return now(); });

  EXPECT_TRUE(limiter.record_reconnect());
  EXPECT_TRUE(limiter.record_reconnect());
  EXPECT_FALSE(limiter.record_reconnect());

  // Advance 61 seconds.
  advance_time(std::chrono::milliseconds(61000));

  EXPECT_TRUE(limiter.record_reconnect());
}

// AdvancedRateLimiter tests.

TEST_F(AdvancedRateLimiterTest, AdvancedRateLimiter_ManagesMultipleClients) {
  RateLimiterConfig config;
  config.bandwidth_bytes_per_sec = 1000000;
  config.packets_per_sec = 10000;

  AdvancedRateLimiter limiter(config, [this]() { return now(); });

  EXPECT_TRUE(limiter.allow_packet("client1", 1000));
  EXPECT_TRUE(limiter.allow_packet("client2", 2000));
  EXPECT_TRUE(limiter.allow_packet("client1", 500));

  auto stats = limiter.get_global_stats();
  EXPECT_EQ(stats.tracked_clients, 2u);
  EXPECT_EQ(stats.total_bytes_allowed, 3500u);
}

TEST_F(AdvancedRateLimiterTest, AdvancedRateLimiter_PerClientConfig) {
  RateLimiterConfig default_config;
  default_config.bandwidth_bytes_per_sec = 1000000;

  RateLimiterConfig special_config;
  special_config.bandwidth_bytes_per_sec = 100;  // Very restrictive.

  AdvancedRateLimiter limiter(default_config, [this]() { return now(); });
  limiter.set_client_config("special_client", special_config);

  // Normal client has high limit.
  EXPECT_TRUE(limiter.allow_packet("normal_client", 10000));

  // Special client has low limit.
  EXPECT_TRUE(limiter.allow_packet("special_client", 100));
  // Next packet should be limited.
  EXPECT_FALSE(limiter.allow_packet("special_client", 100));
}

TEST_F(AdvancedRateLimiterTest, AdvancedRateLimiter_CleanupInactive) {
  RateLimiterConfig config;
  AdvancedRateLimiter limiter(config, [this]() { return now(); });

  limiter.allow_packet("client1", 100);
  limiter.allow_packet("client2", 100);

  EXPECT_EQ(limiter.get_global_stats().tracked_clients, 2u);

  // Advance time past idle threshold.
  advance_time(std::chrono::milliseconds(120000));

  auto removed = limiter.cleanup_inactive(std::chrono::seconds(60));
  EXPECT_EQ(removed, 2u);
  EXPECT_EQ(limiter.get_global_stats().tracked_clients, 0u);
}

TEST_F(AdvancedRateLimiterTest, AdvancedRateLimiter_GetClientStats) {
  RateLimiterConfig config;
  AdvancedRateLimiter limiter(config, [this]() { return now(); });

  limiter.allow_packet("client1", 1000);

  auto stats = limiter.get_client_stats("client1");
  ASSERT_TRUE(stats.has_value());
  EXPECT_EQ(stats->bytes_allowed, 1000u);
  EXPECT_EQ(stats->packets_allowed, 1u);

  auto missing = limiter.get_client_stats("nonexistent");
  EXPECT_FALSE(missing.has_value());
}

TEST_F(AdvancedRateLimiterTest, AdvancedRateLimiter_RemoveClient) {
  RateLimiterConfig config;
  AdvancedRateLimiter limiter(config, [this]() { return now(); });

  limiter.allow_packet("client1", 100);
  limiter.allow_packet("client2", 100);

  limiter.remove_client("client1");

  EXPECT_EQ(limiter.get_global_stats().tracked_clients, 1u);
  EXPECT_FALSE(limiter.get_client_stats("client1").has_value());
  EXPECT_TRUE(limiter.get_client_stats("client2").has_value());
}

}  // namespace veil::utils::test
