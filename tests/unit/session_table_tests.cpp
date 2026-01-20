#include <gtest/gtest.h>

#include <chrono>

#include "server/session_table.h"

namespace veil::server::test {

class SessionTableTest : public ::testing::Test {
 protected:
  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;

  void SetUp() override { current_time_ = Clock::now(); }

  TimePoint now() { return current_time_; }

  void advance_time(std::chrono::seconds seconds) { current_time_ += seconds; }

  TimePoint current_time_;
};

TEST_F(SessionTableTest, CreateSession) {
  SessionTable table(10, std::chrono::seconds(300), "10.8.0.2", "10.8.0.10",
                     [this]() { return now(); });

  transport::UdpEndpoint endpoint{"192.168.1.100", 12345};
  auto transport = std::make_unique<transport::TransportSession>(
      handshake::HandshakeSession{}, transport::TransportSessionConfig{});

  auto session_id = table.create_session(endpoint, std::move(transport));

  ASSERT_TRUE(session_id.has_value());
  EXPECT_GT(*session_id, 0u);
  EXPECT_EQ(table.session_count(), 1u);
  EXPECT_FALSE(table.is_full());
}

TEST_F(SessionTableTest, FindByEndpoint) {
  SessionTable table(10, std::chrono::seconds(300), "10.8.0.2", "10.8.0.10",
                     [this]() { return now(); });

  transport::UdpEndpoint endpoint{"192.168.1.100", 12345};
  auto transport = std::make_unique<transport::TransportSession>(
      handshake::HandshakeSession{}, transport::TransportSessionConfig{});

  auto session_id = table.create_session(endpoint, std::move(transport));
  ASSERT_TRUE(session_id.has_value());

  auto* session = table.find_by_endpoint(endpoint);
  ASSERT_NE(session, nullptr);
  EXPECT_EQ(session->session_id, *session_id);
  EXPECT_EQ(session->endpoint.host, endpoint.host);
  EXPECT_EQ(session->endpoint.port, endpoint.port);
}

TEST_F(SessionTableTest, FindByTunnelIp) {
  SessionTable table(10, std::chrono::seconds(300), "10.8.0.2", "10.8.0.10",
                     [this]() { return now(); });

  transport::UdpEndpoint endpoint{"192.168.1.100", 12345};
  auto transport = std::make_unique<transport::TransportSession>(
      handshake::HandshakeSession{}, transport::TransportSessionConfig{});

  table.create_session(endpoint, std::move(transport));

  // First allocated IP should be from the end of the pool.
  auto* session = table.find_by_tunnel_ip("10.8.0.10");
  ASSERT_NE(session, nullptr);
  EXPECT_EQ(session->tunnel_ip, "10.8.0.10");
}

TEST_F(SessionTableTest, RemoveSession) {
  SessionTable table(10, std::chrono::seconds(300), "10.8.0.2", "10.8.0.10",
                     [this]() { return now(); });

  transport::UdpEndpoint endpoint{"192.168.1.100", 12345};
  auto transport = std::make_unique<transport::TransportSession>(
      handshake::HandshakeSession{}, transport::TransportSessionConfig{});

  auto session_id = table.create_session(endpoint, std::move(transport));
  ASSERT_TRUE(session_id.has_value());
  EXPECT_EQ(table.session_count(), 1u);

  EXPECT_TRUE(table.remove_session(*session_id));
  EXPECT_EQ(table.session_count(), 0u);

  // Session should no longer be findable.
  EXPECT_EQ(table.find_by_id(*session_id), nullptr);
  EXPECT_EQ(table.find_by_endpoint(endpoint), nullptr);
}

TEST_F(SessionTableTest, MaxClients) {
  SessionTable table(3, std::chrono::seconds(300), "10.8.0.2", "10.8.0.10",
                     [this]() { return now(); });

  // Create 3 sessions (max).
  for (int i = 0; i < 3; ++i) {
    transport::UdpEndpoint endpoint{"192.168.1.100", static_cast<std::uint16_t>(12345 + i)};
    auto transport = std::make_unique<transport::TransportSession>(
        handshake::HandshakeSession{}, transport::TransportSessionConfig{});

    auto session_id = table.create_session(endpoint, std::move(transport));
    EXPECT_TRUE(session_id.has_value());
  }

  EXPECT_EQ(table.session_count(), 3u);
  EXPECT_TRUE(table.is_full());

  // Try to create 4th session - should fail.
  transport::UdpEndpoint endpoint{"192.168.1.100", 12400};
  auto transport = std::make_unique<transport::TransportSession>(
      handshake::HandshakeSession{}, transport::TransportSessionConfig{});

  auto session_id = table.create_session(endpoint, std::move(transport));
  EXPECT_FALSE(session_id.has_value());

  // Stats should reflect rejection.
  EXPECT_EQ(table.stats().sessions_rejected_full, 1u);
}

TEST_F(SessionTableTest, CleanupExpired) {
  SessionTable table(10, std::chrono::seconds(60), "10.8.0.2", "10.8.0.10",
                     [this]() { return now(); });

  // Create session.
  transport::UdpEndpoint endpoint{"192.168.1.100", 12345};
  auto transport = std::make_unique<transport::TransportSession>(
      handshake::HandshakeSession{}, transport::TransportSessionConfig{});

  table.create_session(endpoint, std::move(transport));
  EXPECT_EQ(table.session_count(), 1u);

  // Advance time past timeout.
  advance_time(std::chrono::seconds(61));

  // Cleanup should remove the session.
  auto removed = table.cleanup_expired();
  EXPECT_EQ(removed, 1u);
  EXPECT_EQ(table.session_count(), 0u);
  EXPECT_EQ(table.stats().sessions_timed_out, 1u);
}

TEST_F(SessionTableTest, UpdateActivity) {
  SessionTable table(10, std::chrono::seconds(60), "10.8.0.2", "10.8.0.10",
                     [this]() { return now(); });

  transport::UdpEndpoint endpoint{"192.168.1.100", 12345};
  auto transport = std::make_unique<transport::TransportSession>(
      handshake::HandshakeSession{}, transport::TransportSessionConfig{});

  auto session_id = table.create_session(endpoint, std::move(transport));
  ASSERT_TRUE(session_id.has_value());

  // Advance time.
  advance_time(std::chrono::seconds(30));

  // Update activity.
  table.update_activity(*session_id);

  // Advance time more (but not past timeout from last activity).
  advance_time(std::chrono::seconds(40));

  // Cleanup should NOT remove the session (activity was updated).
  auto removed = table.cleanup_expired();
  EXPECT_EQ(removed, 0u);
  EXPECT_EQ(table.session_count(), 1u);
}

TEST_F(SessionTableTest, GetAllSessions) {
  SessionTable table(10, std::chrono::seconds(300), "10.8.0.2", "10.8.0.10",
                     [this]() { return now(); });

  // Create multiple sessions.
  for (int i = 0; i < 5; ++i) {
    transport::UdpEndpoint endpoint{"192.168.1.100", static_cast<std::uint16_t>(12345 + i)};
    auto transport = std::make_unique<transport::TransportSession>(
        handshake::HandshakeSession{}, transport::TransportSessionConfig{});

    table.create_session(endpoint, std::move(transport));
  }

  auto sessions = table.get_all_sessions();
  EXPECT_EQ(sessions.size(), 5u);
}

TEST_F(SessionTableTest, IpPoolExhaustion) {
  // Small IP pool.
  SessionTable table(10, std::chrono::seconds(300), "10.8.0.2", "10.8.0.3",
                     [this]() { return now(); });

  // Create 2 sessions (exhausts pool).
  for (int i = 0; i < 2; ++i) {
    transport::UdpEndpoint endpoint{"192.168.1.100", static_cast<std::uint16_t>(12345 + i)};
    auto transport = std::make_unique<transport::TransportSession>(
        handshake::HandshakeSession{}, transport::TransportSessionConfig{});

    auto session_id = table.create_session(endpoint, std::move(transport));
    EXPECT_TRUE(session_id.has_value());
  }

  // 3rd session should fail - no IPs available.
  transport::UdpEndpoint endpoint{"192.168.1.100", 12400};
  auto transport = std::make_unique<transport::TransportSession>(
      handshake::HandshakeSession{}, transport::TransportSessionConfig{});

  auto session_id = table.create_session(endpoint, std::move(transport));
  EXPECT_FALSE(session_id.has_value());
}

TEST_F(SessionTableTest, IpRecycling) {
  SessionTable table(10, std::chrono::seconds(300), "10.8.0.2", "10.8.0.3",
                     [this]() { return now(); });

  // Create and remove a session.
  transport::UdpEndpoint endpoint1{"192.168.1.100", 12345};
  auto transport1 = std::make_unique<transport::TransportSession>(
      handshake::HandshakeSession{}, transport::TransportSessionConfig{});

  auto session_id1 = table.create_session(endpoint1, std::move(transport1));
  ASSERT_TRUE(session_id1.has_value());

  auto* session1 = table.find_by_id(*session_id1);
  std::string released_ip = session1->tunnel_ip;

  table.remove_session(*session_id1);

  // Create new session - should get the recycled IP.
  transport::UdpEndpoint endpoint2{"192.168.1.101", 12346};
  auto transport2 = std::make_unique<transport::TransportSession>(
      handshake::HandshakeSession{}, transport::TransportSessionConfig{});

  auto session_id2 = table.create_session(endpoint2, std::move(transport2));
  ASSERT_TRUE(session_id2.has_value());

  auto* session2 = table.find_by_id(*session_id2);
  EXPECT_EQ(session2->tunnel_ip, released_ip);
}

TEST_F(SessionTableTest, Statistics) {
  SessionTable table(10, std::chrono::seconds(60), "10.8.0.2", "10.8.0.10",
                     [this]() { return now(); });

  // Initial stats.
  EXPECT_EQ(table.stats().active_sessions, 0u);
  EXPECT_EQ(table.stats().total_sessions_created, 0u);

  // Create session.
  transport::UdpEndpoint endpoint{"192.168.1.100", 12345};
  auto transport = std::make_unique<transport::TransportSession>(
      handshake::HandshakeSession{}, transport::TransportSessionConfig{});

  table.create_session(endpoint, std::move(transport));

  EXPECT_EQ(table.stats().active_sessions, 1u);
  EXPECT_EQ(table.stats().total_sessions_created, 1u);

  // Let it expire.
  advance_time(std::chrono::seconds(61));
  table.cleanup_expired();

  EXPECT_EQ(table.stats().active_sessions, 0u);
  EXPECT_EQ(table.stats().sessions_timed_out, 1u);
}

}  // namespace veil::server::test
