#include <gtest/gtest.h>

#include <chrono>

#include "common/session/session_lifecycle.h"

namespace veil::session::test {

class SessionLifecycleTest : public ::testing::Test {
 protected:
  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;

  void SetUp() override { current_time_ = Clock::now(); }

  TimePoint now() { return current_time_; }

  void advance_time(std::chrono::seconds sec) { current_time_ += sec; }

  TimePoint current_time_;
};

TEST_F(SessionLifecycleTest, StateToString) {
  EXPECT_STREQ(session_state_to_string(SessionState::kActive), "active");
  EXPECT_STREQ(session_state_to_string(SessionState::kDraining), "draining");
  EXPECT_STREQ(session_state_to_string(SessionState::kExpired), "expired");
  EXPECT_STREQ(session_state_to_string(SessionState::kTerminated), "terminated");
}

TEST_F(SessionLifecycleTest, InitialState) {
  SessionLifecycleConfig config;
  SessionLifecycle lifecycle(1, config, {}, [this]() { return now(); });

  EXPECT_EQ(lifecycle.session_id(), 1u);
  EXPECT_EQ(lifecycle.state(), SessionState::kActive);
  EXPECT_TRUE(lifecycle.is_alive());
  EXPECT_TRUE(lifecycle.can_accept_data());
}

TEST_F(SessionLifecycleTest, RecordActivity) {
  SessionLifecycleConfig config;
  config.idle_timeout = std::chrono::seconds(60);

  SessionLifecycle lifecycle(1, config, {}, [this]() { return now(); });

  advance_time(std::chrono::seconds(30));
  lifecycle.record_activity();

  advance_time(std::chrono::seconds(40));
  EXPECT_FALSE(lifecycle.check_timeouts());  // Should not expire.
  EXPECT_EQ(lifecycle.state(), SessionState::kActive);
}

TEST_F(SessionLifecycleTest, IdleTimeout) {
  SessionLifecycleConfig config;
  config.idle_timeout = std::chrono::seconds(60);

  bool expired_called = false;
  SessionLifecycleCallbacks callbacks;
  callbacks.on_expired = [&expired_called](std::uint64_t) { expired_called = true; };

  SessionLifecycle lifecycle(1, config, callbacks, [this]() { return now(); });

  advance_time(std::chrono::seconds(61));
  EXPECT_TRUE(lifecycle.check_timeouts());
  EXPECT_EQ(lifecycle.state(), SessionState::kExpired);
  EXPECT_TRUE(expired_called);
  EXPECT_FALSE(lifecycle.is_alive());
}

TEST_F(SessionLifecycleTest, AbsoluteTimeout) {
  SessionLifecycleConfig config;
  config.idle_timeout = std::chrono::seconds(3600);
  config.absolute_timeout = std::chrono::seconds(100);

  SessionLifecycle lifecycle(1, config, {}, [this]() { return now(); });

  // Keep session active.
  advance_time(std::chrono::seconds(50));
  lifecycle.record_activity();

  advance_time(std::chrono::seconds(51));
  lifecycle.record_activity();  // Activity won't prevent absolute timeout.

  EXPECT_TRUE(lifecycle.check_timeouts());
  EXPECT_EQ(lifecycle.state(), SessionState::kExpired);
}

TEST_F(SessionLifecycleTest, IdleWarning) {
  SessionLifecycleConfig config;
  config.idle_warning = std::chrono::seconds(50);
  config.idle_timeout = std::chrono::seconds(60);

  bool warning_called = false;
  SessionLifecycleCallbacks callbacks;
  callbacks.on_idle_warning = [&warning_called](std::uint64_t) { warning_called = true; };

  SessionLifecycle lifecycle(1, config, callbacks, [this]() { return now(); });

  advance_time(std::chrono::seconds(51));
  lifecycle.check_timeouts();
  EXPECT_TRUE(warning_called);
  EXPECT_EQ(lifecycle.state(), SessionState::kActive);  // Not expired yet.
}

TEST_F(SessionLifecycleTest, StartDrain) {
  SessionLifecycleConfig config;
  config.drain_timeout = std::chrono::seconds(5);

  bool draining_called = false;
  SessionLifecycleCallbacks callbacks;
  callbacks.on_draining = [&draining_called](std::uint64_t) { draining_called = true; };

  SessionLifecycle lifecycle(1, config, callbacks, [this]() { return now(); });

  lifecycle.start_drain();
  EXPECT_TRUE(draining_called);
  EXPECT_EQ(lifecycle.state(), SessionState::kDraining);
  EXPECT_TRUE(lifecycle.is_alive());
  EXPECT_FALSE(lifecycle.can_accept_data());
}

TEST_F(SessionLifecycleTest, DrainTimeout) {
  SessionLifecycleConfig config;
  config.drain_timeout = std::chrono::seconds(5);

  SessionLifecycle lifecycle(1, config, {}, [this]() { return now(); });

  lifecycle.start_drain();
  EXPECT_EQ(lifecycle.state(), SessionState::kDraining);

  advance_time(std::chrono::seconds(6));
  lifecycle.check_timeouts();
  EXPECT_EQ(lifecycle.state(), SessionState::kExpired);
}

TEST_F(SessionLifecycleTest, Terminate) {
  SessionLifecycleConfig config;

  bool terminated_called = false;
  SessionLifecycleCallbacks callbacks;
  callbacks.on_terminated = [&terminated_called](std::uint64_t) { terminated_called = true; };

  SessionLifecycle lifecycle(1, config, callbacks, [this]() { return now(); });

  lifecycle.terminate();
  EXPECT_TRUE(terminated_called);
  EXPECT_EQ(lifecycle.state(), SessionState::kTerminated);
  EXPECT_FALSE(lifecycle.is_alive());
}

TEST_F(SessionLifecycleTest, MemoryTracking) {
  SessionLifecycleConfig config;
  config.max_memory_per_session = 1000;

  bool memory_exceeded = false;
  SessionLifecycleCallbacks callbacks;
  callbacks.on_memory_exceeded = [&memory_exceeded](std::uint64_t, std::size_t, std::size_t) {
    memory_exceeded = true;
  };

  SessionLifecycle lifecycle(1, config, callbacks, [this]() { return now(); });

  lifecycle.update_memory_usage(500);
  EXPECT_FALSE(memory_exceeded);
  EXPECT_EQ(lifecycle.stats().current_memory, 500u);

  lifecycle.update_memory_usage(1500);
  EXPECT_TRUE(memory_exceeded);
  EXPECT_EQ(lifecycle.stats().peak_memory, 1500u);
}

TEST_F(SessionLifecycleTest, QueueTracking) {
  SessionLifecycleConfig config;
  config.max_packet_queue = 10;

  bool queue_full = false;
  SessionLifecycleCallbacks callbacks;
  callbacks.on_queue_full = [&queue_full](std::uint64_t, std::size_t) { queue_full = true; };

  SessionLifecycle lifecycle(1, config, callbacks, [this]() { return now(); });

  for (int i = 0; i < 10; i++) {
    lifecycle.record_queued_packet();
  }
  EXPECT_FALSE(queue_full);

  lifecycle.record_queued_packet();
  EXPECT_TRUE(queue_full);

  lifecycle.record_dequeued_packet();
  EXPECT_EQ(lifecycle.stats().current_queue_size, 10u);
}

TEST_F(SessionLifecycleTest, TimeUntilTimeout) {
  SessionLifecycleConfig config;
  config.idle_timeout = std::chrono::seconds(60);

  SessionLifecycle lifecycle(1, config, {}, [this]() { return now(); });

  auto remaining = lifecycle.time_until_idle_timeout();
  EXPECT_EQ(remaining.count(), 60);

  advance_time(std::chrono::seconds(30));
  remaining = lifecycle.time_until_idle_timeout();
  EXPECT_EQ(remaining.count(), 30);
}

TEST_F(SessionLifecycleTest, SessionAge) {
  SessionLifecycleConfig config;

  SessionLifecycle lifecycle(1, config, {}, [this]() { return now(); });

  advance_time(std::chrono::seconds(100));
  EXPECT_EQ(lifecycle.age().count(), 100);
}

// SessionLifecycleManager tests.

TEST_F(SessionLifecycleTest, Manager_CreateSession) {
  SessionLifecycleConfig config;
  SessionLifecycleManager manager(config, [this]() { return now(); });

  auto& session1 = manager.create_session(1);
  auto& session2 = manager.create_session(2);

  EXPECT_EQ(session1.session_id(), 1u);
  EXPECT_EQ(session2.session_id(), 2u);

  auto counts = manager.get_counts();
  EXPECT_EQ(counts.total, 2u);
  EXPECT_EQ(counts.active, 2u);
}

TEST_F(SessionLifecycleTest, Manager_GetSession) {
  SessionLifecycleManager manager({}, [this]() { return now(); });

  manager.create_session(1);

  auto* session = manager.get_session(1);
  ASSERT_NE(session, nullptr);
  EXPECT_EQ(session->session_id(), 1u);

  auto* missing = manager.get_session(999);
  EXPECT_EQ(missing, nullptr);
}

TEST_F(SessionLifecycleTest, Manager_RemoveSession) {
  SessionLifecycleManager manager({}, [this]() { return now(); });

  manager.create_session(1);
  EXPECT_EQ(manager.get_counts().total, 1u);

  EXPECT_TRUE(manager.remove_session(1));
  EXPECT_EQ(manager.get_counts().total, 0u);

  EXPECT_FALSE(manager.remove_session(1));  // Already removed.
}

TEST_F(SessionLifecycleTest, Manager_CheckAllTimeouts) {
  SessionLifecycleConfig config;
  config.idle_timeout = std::chrono::seconds(60);

  SessionLifecycleManager manager(config, [this]() { return now(); });

  manager.create_session(1);
  manager.create_session(2);

  // Keep session 1 active.
  advance_time(std::chrono::seconds(30));
  manager.get_session(1)->record_activity();

  advance_time(std::chrono::seconds(31));
  auto changed = manager.check_all_timeouts();

  EXPECT_EQ(changed.size(), 1u);  // Only session 2 should expire.
  EXPECT_EQ(changed[0], 2u);
}

TEST_F(SessionLifecycleTest, Manager_DrainAll) {
  SessionLifecycleManager manager({}, [this]() { return now(); });

  manager.create_session(1);
  manager.create_session(2);

  manager.drain_all();

  auto counts = manager.get_counts();
  EXPECT_EQ(counts.draining, 2u);
  EXPECT_EQ(counts.active, 0u);
}

TEST_F(SessionLifecycleTest, Manager_TerminateAll) {
  SessionLifecycleManager manager({}, [this]() { return now(); });

  manager.create_session(1);
  manager.create_session(2);

  manager.terminate_all();

  auto counts = manager.get_counts();
  EXPECT_EQ(counts.terminated, 2u);
}

TEST_F(SessionLifecycleTest, Manager_Cleanup) {
  SessionLifecycleConfig config;
  config.idle_timeout = std::chrono::seconds(60);

  SessionLifecycleManager manager(config, [this]() { return now(); });

  manager.create_session(1);
  manager.create_session(2);
  manager.create_session(3);

  // Terminate session 1 immediately.
  manager.get_session(1)->terminate();

  // Keep session 3 active before idle check.
  advance_time(std::chrono::seconds(30));
  manager.get_session(3)->record_activity();

  // Session 2 will expire after 61 seconds (only 31 more seconds for session 3).
  advance_time(std::chrono::seconds(31));
  manager.check_all_timeouts();  // Sessions 1 and 2 should be removable.

  auto removed = manager.cleanup();
  EXPECT_EQ(removed, 2u);
  EXPECT_EQ(manager.get_counts().total, 1u);
}

TEST_F(SessionLifecycleTest, Manager_GetSessionsInState) {
  SessionLifecycleManager manager({}, [this]() { return now(); });

  manager.create_session(1);
  manager.create_session(2);
  manager.create_session(3);

  manager.get_session(1)->start_drain();
  manager.get_session(2)->terminate();

  auto active = manager.get_sessions_in_state(SessionState::kActive);
  EXPECT_EQ(active.size(), 1u);
  EXPECT_EQ(active[0], 3u);

  auto draining = manager.get_sessions_in_state(SessionState::kDraining);
  EXPECT_EQ(draining.size(), 1u);
  EXPECT_EQ(draining[0], 1u);
}

}  // namespace veil::session::test
