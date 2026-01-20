#include <gtest/gtest.h>

#include <chrono>
#include <thread>

#include "common/session/idle_timeout.h"
#include "common/session/session_lifecycle.h"
#include "common/utils/advanced_rate_limiter.h"
#include "common/utils/graceful_degradation.h"

namespace veil::integration {

class ReliabilityIntegrationTest : public ::testing::Test {
 protected:
  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;

  void SetUp() override { current_time_ = Clock::now(); }

  TimePoint now() { return current_time_; }

  void advance_time(std::chrono::milliseconds ms) { current_time_ += ms; }

  TimePoint current_time_;
};

// Test graceful shutdown with session lifecycle.
TEST_F(ReliabilityIntegrationTest, GracefulShutdown) {
  session::SessionLifecycleConfig config;
  config.drain_timeout = std::chrono::seconds(5);

  session::SessionLifecycleManager manager(config, [this]() { return now(); });

  // Create multiple sessions.
  for (int i = 1; i <= 10; i++) {
    manager.create_session(static_cast<std::uint64_t>(i));
  }

  auto counts = manager.get_counts();
  EXPECT_EQ(counts.active, 10u);
  EXPECT_EQ(counts.draining, 0u);

  // Initiate graceful shutdown.
  manager.drain_all();

  counts = manager.get_counts();
  EXPECT_EQ(counts.active, 0u);
  EXPECT_EQ(counts.draining, 10u);

  // Advance time past drain timeout.
  advance_time(std::chrono::milliseconds(6000));
  manager.check_all_timeouts();

  counts = manager.get_counts();
  EXPECT_EQ(counts.draining, 0u);
  EXPECT_EQ(counts.expired, 10u);

  // Cleanup.
  auto removed = manager.cleanup();
  EXPECT_EQ(removed, 10u);
  EXPECT_EQ(manager.get_counts().total, 0u);
}

// Test session cleanup with mixed states.
TEST_F(ReliabilityIntegrationTest, MixedSessionCleanup) {
  session::SessionLifecycleConfig config;
  config.idle_timeout = std::chrono::seconds(60);
  config.absolute_timeout = std::chrono::seconds(3600);

  session::SessionLifecycleManager manager(config, [this]() { return now(); });

  // Create sessions.
  manager.create_session(1);
  manager.create_session(2);
  manager.create_session(3);
  manager.create_session(4);

  // Session 1: Keep active.
  // Session 2: Let idle timeout.
  // Session 3: Start draining.
  // Session 4: Terminate immediately.

  advance_time(std::chrono::milliseconds(30000));
  manager.get_session(1)->record_activity();

  manager.get_session(3)->start_drain();
  manager.get_session(4)->terminate();

  advance_time(std::chrono::milliseconds(31000));  // Past idle timeout.
  manager.check_all_timeouts();

  auto counts = manager.get_counts();
  EXPECT_EQ(counts.active, 1u);     // Session 1.
  EXPECT_EQ(counts.expired, 2u);    // Sessions 2 and 3.
  EXPECT_EQ(counts.terminated, 1u); // Session 4.

  // Cleanup expired and terminated.
  auto removed = manager.cleanup();
  EXPECT_EQ(removed, 3u);

  // Only session 1 remains.
  EXPECT_EQ(manager.get_counts().total, 1u);
  EXPECT_NE(manager.get_session(1), nullptr);
}

// Test rate limiting with multiple clients.
TEST_F(ReliabilityIntegrationTest, MultiClientRateLimiting) {
  utils::RateLimiterConfig config;
  config.bandwidth_bytes_per_sec = 10000;
  config.packets_per_sec = 100;
  config.burst_allowance_factor = 1.0;  // No burst.

  utils::AdvancedRateLimiter limiter(config, [this]() { return now(); });

  // Simulate multiple clients.
  for (int client = 0; client < 5; client++) {
    std::string client_id = "client_" + std::to_string(client);

    // Each client sends packets.
    int allowed = 0;
    for (int i = 0; i < 200; i++) {
      if (limiter.allow_packet(client_id, 100)) {
        allowed++;
      }
    }

    // Should allow approximately 100 packets (bandwidth limit).
    EXPECT_GE(allowed, 80);
    EXPECT_LE(allowed, 120);
  }

  auto stats = limiter.get_global_stats();
  EXPECT_EQ(stats.tracked_clients, 5u);
}

// Test rate limiting with per-client config.
TEST_F(ReliabilityIntegrationTest, PerClientRateLimiting) {
  utils::RateLimiterConfig default_config;
  default_config.bandwidth_bytes_per_sec = 100000;
  default_config.packets_per_sec = 1000;

  utils::RateLimiterConfig restricted_config;
  restricted_config.bandwidth_bytes_per_sec = 1000;
  restricted_config.packets_per_sec = 10;

  utils::AdvancedRateLimiter limiter(default_config, [this]() { return now(); });
  limiter.set_client_config("restricted_client", restricted_config);

  // Normal client.
  int normal_allowed = 0;
  for (int i = 0; i < 100; i++) {
    if (limiter.allow_packet("normal_client", 100)) {
      normal_allowed++;
    }
  }

  // Restricted client.
  int restricted_allowed = 0;
  for (int i = 0; i < 100; i++) {
    if (limiter.allow_packet("restricted_client", 100)) {
      restricted_allowed++;
    }
  }

  EXPECT_GT(normal_allowed, restricted_allowed);
  EXPECT_LE(restricted_allowed, 20);  // Much more limited.
}

// Test graceful degradation with system overload.
TEST_F(ReliabilityIntegrationTest, GracefulDegradationOverload) {
  utils::DegradationConfig config;
  config.cpu_moderate_threshold = 50.0;
  config.cpu_severe_threshold = 75.0;
  config.cpu_critical_threshold = 90.0;
  config.escalation_delay = std::chrono::seconds(1);
  config.recovery_delay = std::chrono::seconds(2);

  std::vector<utils::DegradationLevel> level_changes;
  utils::DegradationCallbacks callbacks;
  callbacks.on_level_change = [&level_changes]([[maybe_unused]] utils::DegradationLevel old_level,
                                                utils::DegradationLevel new_level) {
    level_changes.push_back(new_level);
  };

  utils::GracefulDegradation degradation(config, callbacks, [this]() { return now(); });

  // Initial state.
  EXPECT_EQ(degradation.level(), utils::DegradationLevel::kNormal);
  EXPECT_TRUE(degradation.should_accept_connections());

  // Simulate moderate load.
  utils::SystemMetrics metrics;
  metrics.cpu_usage_percent = 60.0;
  advance_time(std::chrono::milliseconds(1500));
  degradation.update(metrics);

  EXPECT_EQ(degradation.level(), utils::DegradationLevel::kModerate);

  // Simulate severe load.
  metrics.cpu_usage_percent = 80.0;
  advance_time(std::chrono::milliseconds(1500));
  degradation.update(metrics);

  EXPECT_EQ(degradation.level(), utils::DegradationLevel::kSevere);
  EXPECT_FALSE(degradation.should_accept_connections());

  // Recovery.
  metrics.cpu_usage_percent = 30.0;
  advance_time(std::chrono::milliseconds(3000));
  degradation.update(metrics);

  EXPECT_EQ(degradation.level(), utils::DegradationLevel::kNormal);
  EXPECT_TRUE(degradation.should_accept_connections());
}

// Test idle timeout with keep-alive probes.
TEST_F(ReliabilityIntegrationTest, IdleTimeoutWithKeepalive) {
  session::IdleTimeoutConfig config;
  config.warning_threshold = std::chrono::seconds(50);
  config.soft_close_threshold = std::chrono::seconds(60);
  config.forced_close_threshold = std::chrono::seconds(70);
  config.keepalive_interval = std::chrono::seconds(15);
  config.max_missed_probes = 3;
  config.enable_keepalive = true;

  bool warning_received = false;
  bool soft_close_received = false;
  bool keepalive_sent = false;

  session::IdleTimeoutCallbacks callbacks;
  callbacks.on_warning = [&warning_received]() { warning_received = true; };
  callbacks.on_soft_close = [&soft_close_received]() { soft_close_received = true; };
  callbacks.on_send_keepalive = [&keepalive_sent]() { keepalive_sent = true; };

  session::IdleTimeout timeout(config, callbacks, [this]() { return now(); });

  // Advance to trigger keepalive.
  advance_time(std::chrono::milliseconds(16000));
  timeout.check();
  EXPECT_TRUE(keepalive_sent);

  // Simulate keepalive response - resets idle.
  timeout.record_keepalive_response();

  // Advance but not past warning.
  advance_time(std::chrono::milliseconds(40000));
  timeout.check();
  EXPECT_FALSE(warning_received);

  // Advance past warning.
  advance_time(std::chrono::milliseconds(15000));
  timeout.check();
  EXPECT_TRUE(warning_received);

  // Activity resets idle.
  timeout.record_rx();
  warning_received = false;

  advance_time(std::chrono::milliseconds(40000));
  timeout.check();
  EXPECT_FALSE(warning_received);  // Reset by activity.
}

// Test combined session lifecycle and idle timeout.
TEST_F(ReliabilityIntegrationTest, SessionWithIdleTimeout) {
  session::SessionLifecycleConfig lifecycle_config;
  lifecycle_config.idle_timeout = std::chrono::seconds(60);
  lifecycle_config.idle_warning = std::chrono::seconds(50);

  session::IdleTimeoutConfig idle_config;
  idle_config.warning_threshold = std::chrono::seconds(50);
  idle_config.soft_close_threshold = std::chrono::seconds(60);
  idle_config.forced_close_threshold = std::chrono::seconds(70);

  session::SessionLifecycleManager manager(lifecycle_config, [this]() { return now(); });
  auto& session = manager.create_session(1);

  // Session is active.
  EXPECT_EQ(session.state(), session::SessionState::kActive);

  // Simulate traffic.
  for (int i = 0; i < 5; i++) {
    advance_time(std::chrono::milliseconds(10000));
    session.record_rx(1000);
    session.record_tx(500);
  }

  // Session still active.
  EXPECT_EQ(session.state(), session::SessionState::kActive);
  EXPECT_EQ(session.stats().bytes_received, 5000u);
  EXPECT_EQ(session.stats().bytes_sent, 2500u);

  // Let it idle.
  advance_time(std::chrono::milliseconds(61000));
  manager.check_all_timeouts();

  EXPECT_EQ(session.state(), session::SessionState::kExpired);
}

// Test degradation actions.
TEST_F(ReliabilityIntegrationTest, DegradationActions) {
  auto normal_actions = utils::get_default_actions(utils::DegradationLevel::kNormal);
  auto moderate_actions = utils::get_default_actions(utils::DegradationLevel::kModerate);
  auto severe_actions = utils::get_default_actions(utils::DegradationLevel::kSevere);
  auto critical_actions = utils::get_default_actions(utils::DegradationLevel::kCritical);

  // Normal.
  EXPECT_DOUBLE_EQ(normal_actions.heartbeat_multiplier, 1.0);
  EXPECT_EQ(normal_actions.ack_batch_factor, 1u);
  EXPECT_TRUE(normal_actions.accept_new_connections);
  EXPECT_FALSE(normal_actions.drop_low_priority);

  // Moderate.
  EXPECT_GT(moderate_actions.heartbeat_multiplier, 1.0);
  EXPECT_GT(moderate_actions.ack_batch_factor, 1u);
  EXPECT_TRUE(moderate_actions.accept_new_connections);
  EXPECT_TRUE(moderate_actions.drop_low_priority);

  // Severe.
  EXPECT_FALSE(severe_actions.accept_new_connections);
  EXPECT_TRUE(severe_actions.drop_low_priority);

  // Critical.
  EXPECT_FALSE(critical_actions.accept_new_connections);
  EXPECT_TRUE(critical_actions.max_concurrent_ops.has_value());
}

}  // namespace veil::integration
