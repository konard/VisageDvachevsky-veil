#include <gtest/gtest.h>

#include <chrono>
#include <thread>

#include "common/logging/constrained_logger.h"

namespace veil::logging::test {

class ConstrainedLoggingTest : public ::testing::Test {
 protected:
  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;

  void SetUp() override { current_time_ = Clock::now(); }

  TimePoint now() { return current_time_; }

  void advance_time(std::chrono::milliseconds ms) { current_time_ += ms; }

  TimePoint current_time_;
};

// LogRateLimiter tests.

TEST_F(ConstrainedLoggingTest, RateLimiter_AllowsWithinLimit) {
  LogRateLimiter limiter(100, [this]() { return now(); });

  for (int i = 0; i < 100; i++) {
    EXPECT_TRUE(limiter.allow());
  }
}

TEST_F(ConstrainedLoggingTest, RateLimiter_BlocksOverLimit) {
  LogRateLimiter limiter(10, [this]() { return now(); });

  for (int i = 0; i < 10; i++) {
    EXPECT_TRUE(limiter.allow());
  }
  EXPECT_FALSE(limiter.allow());
}

TEST_F(ConstrainedLoggingTest, RateLimiter_ResetsAfterSecond) {
  LogRateLimiter limiter(10, [this]() { return now(); });

  for (int i = 0; i < 10; i++) {
    limiter.allow();
  }
  EXPECT_FALSE(limiter.allow());

  advance_time(std::chrono::milliseconds(1001));
  EXPECT_TRUE(limiter.allow());
}

TEST_F(ConstrainedLoggingTest, RateLimiter_TracksDropped) {
  LogRateLimiter limiter(5, [this]() { return now(); });

  for (int i = 0; i < 10; i++) {
    limiter.allow();
  }

  EXPECT_EQ(limiter.dropped_count(), 5u);
}

TEST_F(ConstrainedLoggingTest, RateLimiter_UnlimitedWhenZero) {
  LogRateLimiter limiter(0, [this]() { return now(); });

  for (int i = 0; i < 1000; i++) {
    EXPECT_TRUE(limiter.allow());
  }
}

// LogSampler tests.

TEST_F(ConstrainedLoggingTest, Sampler_AllowsAllWhenRateOne) {
  LogSampler sampler(1.0);

  for (int i = 0; i < 100; i++) {
    EXPECT_TRUE(sampler.sample());
  }

  EXPECT_EQ(sampler.sampled_count(), 100u);
  EXPECT_EQ(sampler.skipped_count(), 0u);
}

TEST_F(ConstrainedLoggingTest, Sampler_BlocksAllWhenRateZero) {
  LogSampler sampler(0.0);

  for (int i = 0; i < 100; i++) {
    EXPECT_FALSE(sampler.sample());
  }

  EXPECT_EQ(sampler.sampled_count(), 0u);
  EXPECT_EQ(sampler.skipped_count(), 100u);
}

TEST_F(ConstrainedLoggingTest, Sampler_SamplesAtRate) {
  LogSampler sampler(0.1);  // 10% sampling rate.

  int sampled = 0;
  for (int i = 0; i < 100; i++) {
    if (sampler.sample()) {
      sampled++;
    }
  }

  // Should sample approximately 10 entries (with some tolerance).
  EXPECT_GE(sampled, 5);
  EXPECT_LE(sampled, 15);
}

// StructuredFormatter tests.

TEST_F(ConstrainedLoggingTest, StructuredFormatter_ToJson) {
  LogEntry entry;
  entry.level = LogLevel::info;
  entry.message = "test message";
  entry.location = "test.cpp:42";
  entry.timestamp = Clock::now();

  auto json = StructuredFormatter::to_json(entry);

  EXPECT_NE(json.find("\"level\":\"info\""), std::string::npos);
  EXPECT_NE(json.find("\"message\":\"test message\""), std::string::npos);
  EXPECT_NE(json.find("\"location\":\"test.cpp:42\""), std::string::npos);
}

TEST_F(ConstrainedLoggingTest, StructuredFormatter_EscapesSpecialChars) {
  LogEntry entry;
  entry.level = LogLevel::info;
  entry.message = "test \"quoted\" message\nwith newline";
  entry.timestamp = Clock::now();

  auto json = StructuredFormatter::to_json(entry);

  EXPECT_NE(json.find("\\\"quoted\\\""), std::string::npos);
  EXPECT_NE(json.find("\\n"), std::string::npos);
}

TEST_F(ConstrainedLoggingTest, StructuredFormatter_WithContext) {
  LogEntry entry;
  entry.level = LogLevel::warn;
  entry.message = "warning";
  entry.timestamp = Clock::now();

  std::unordered_map<std::string, std::string> context;
  context["session_id"] = "12345";
  context["client_ip"] = "192.168.1.1";

  auto json = StructuredFormatter::to_json(entry, context);

  EXPECT_NE(json.find("\"session_id\":\"12345\""), std::string::npos);
  EXPECT_NE(json.find("\"client_ip\":\"192.168.1.1\""), std::string::npos);
}

TEST_F(ConstrainedLoggingTest, StructuredFormatter_LevelToString) {
  EXPECT_STREQ(StructuredFormatter::level_to_string(LogLevel::trace), "trace");
  EXPECT_STREQ(StructuredFormatter::level_to_string(LogLevel::debug), "debug");
  EXPECT_STREQ(StructuredFormatter::level_to_string(LogLevel::info), "info");
  EXPECT_STREQ(StructuredFormatter::level_to_string(LogLevel::warn), "warn");
  EXPECT_STREQ(StructuredFormatter::level_to_string(LogLevel::error), "error");
  EXPECT_STREQ(StructuredFormatter::level_to_string(LogLevel::critical), "critical");
}

// ConstrainedLogger tests.

TEST_F(ConstrainedLoggingTest, Logger_LevelFiltering) {
  ConstrainedLoggerConfig config;
  config.min_level = LogLevel::warn;
  config.async_logging = false;

  ConstrainedLogger logger(config, [this]() { return now(); });

  EXPECT_FALSE(logger.is_level_enabled(LogLevel::debug));
  EXPECT_FALSE(logger.is_level_enabled(LogLevel::info));
  EXPECT_TRUE(logger.is_level_enabled(LogLevel::warn));
  EXPECT_TRUE(logger.is_level_enabled(LogLevel::error));
}

TEST_F(ConstrainedLoggingTest, Logger_TracksStats) {
  ConstrainedLoggerConfig config;
  config.min_level = LogLevel::info;
  config.rate_limit_per_sec = 100;
  config.async_logging = false;

  ConstrainedLogger logger(config, [this]() { return now(); });

  logger.log(LogLevel::info, "test1");
  logger.log(LogLevel::info, "test2");

  auto stats = logger.get_stats();
  EXPECT_EQ(stats.total_logged, 2u);
}

TEST_F(ConstrainedLoggingTest, Logger_RateLimits) {
  ConstrainedLoggerConfig config;
  config.min_level = LogLevel::info;
  config.rate_limit_per_sec = 5;
  config.async_logging = false;

  ConstrainedLogger logger(config, [this]() { return now(); });

  for (int i = 0; i < 10; i++) {
    logger.log(LogLevel::info, "test");
  }

  auto stats = logger.get_stats();
  EXPECT_EQ(stats.total_logged, 5u);
  EXPECT_EQ(stats.rate_limited, 5u);
}

TEST_F(ConstrainedLoggingTest, Logger_SampledLogging) {
  ConstrainedLoggerConfig config;
  config.min_level = LogLevel::info;
  config.rate_limit_per_sec = 0;  // Unlimited.
  config.sampling_rate = 0.1;     // 10% sampling.
  config.async_logging = false;

  ConstrainedLogger logger(config, [this]() { return now(); });

  for (int i = 0; i < 100; i++) {
    logger.log_sampled(LogLevel::info, "sampled message");
  }

  auto stats = logger.get_stats();
  // Should have logged approximately 10 messages.
  EXPECT_GE(stats.total_logged, 5u);
  EXPECT_LE(stats.total_logged, 15u);
  EXPECT_GE(stats.sampled_out, 85u);
}

TEST_F(ConstrainedLoggingTest, Logger_PriorityCategoriesBypassRateLimit) {
  ConstrainedLoggerConfig config;
  config.min_level = LogLevel::info;
  config.rate_limit_per_sec = 2;
  config.priority_categories = {"security", "auth"};
  config.async_logging = false;

  ConstrainedLogger logger(config, [this]() { return now(); });

  // These should be rate limited.
  logger.log(LogLevel::info, "normal1", "general");
  logger.log(LogLevel::info, "normal2", "general");
  logger.log(LogLevel::info, "normal3", "general");  // Rate limited.

  // These should bypass rate limiting.
  logger.log(LogLevel::info, "security1", "security");
  logger.log(LogLevel::info, "security2", "security");
  logger.log(LogLevel::info, "auth1", "auth");

  auto stats = logger.get_stats();
  EXPECT_EQ(stats.total_logged, 5u);  // 2 normal + 3 priority.
  EXPECT_EQ(stats.rate_limited, 1u);
}

TEST_F(ConstrainedLoggingTest, Logger_Context) {
  ConstrainedLoggerConfig config;
  config.async_logging = false;
  config.structured_logging = true;

  ConstrainedLogger logger(config, [this]() { return now(); });

  logger.set_context("service", "veil-server");
  logger.set_context("version", "1.0");

  // Context is internal - we just verify it doesn't crash.
  logger.log(LogLevel::info, "test with context");

  logger.clear_context();
  logger.log(LogLevel::info, "test without context");
}

TEST_F(ConstrainedLoggingTest, Logger_UpdateConfig) {
  ConstrainedLoggerConfig config;
  config.min_level = LogLevel::info;
  config.rate_limit_per_sec = 100;
  config.async_logging = false;

  ConstrainedLogger logger(config, [this]() { return now(); });

  EXPECT_FALSE(logger.is_level_enabled(LogLevel::debug));

  ConstrainedLoggerConfig new_config;
  new_config.min_level = LogLevel::debug;
  new_config.async_logging = false;

  logger.update_config(new_config);

  EXPECT_TRUE(logger.is_level_enabled(LogLevel::debug));
}

}  // namespace veil::logging::test
