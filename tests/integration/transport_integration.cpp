#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <future>
#include <thread>
#include <vector>

#include "common/handshake/handshake_processor.h"
#include "common/utils/rate_limiter.h"
#include "transport/session/transport_session.h"
#include "transport/udp_socket/udp_socket.h"

namespace veil::integration_tests {

using namespace std::chrono_literals;

// Helper function to check if netem is available (requires root).
static bool is_netem_available() {
  // In CI or unprivileged environments, skip netem setup.
  const char* skip_netem = std::getenv("VEIL_SKIP_NETEM");
  if (skip_netem != nullptr) {
    return false;
  }
  // Try a dry-run tc command.
  const int result = std::system("tc -n qdisc show dev lo >/dev/null 2>&1");
  return result == 0;
}

// Test fixture for transport integration tests.
class TransportIntegrationTest : public ::testing::Test {
 protected:
  void SetUp() override {
    now_ = std::chrono::system_clock::now();
    steady_now_ = std::chrono::steady_clock::now();

    auto now_fn = [this]() { return now_; };
    auto steady_fn = [this]() { return steady_now_; };

    psk_ = std::vector<std::uint8_t>(32, 0xAB);

    // Perform handshake to get session keys.
    handshake::HandshakeInitiator initiator(psk_, 200ms, now_fn);
    utils::TokenBucket bucket(100.0, 1000ms, steady_fn);
    handshake::HandshakeResponder responder(psk_, 200ms, std::move(bucket), now_fn);

    auto init_bytes = initiator.create_init();
    now_ += 10ms;
    steady_now_ += 10ms;
    auto resp = responder.handle_init(init_bytes);
    ASSERT_TRUE(resp.has_value());

    now_ += 10ms;
    steady_now_ += 10ms;
    auto client_session = initiator.consume_response(resp->response);
    ASSERT_TRUE(client_session.has_value());

    client_handshake_ = *client_session;
    server_handshake_ = resp->session;
  }

  std::chrono::system_clock::time_point now_;
  std::chrono::steady_clock::time_point steady_now_;
  std::vector<std::uint8_t> psk_;
  handshake::HandshakeSession client_handshake_;
  handshake::HandshakeSession server_handshake_;
};

// Test basic loopback communication between client and server.
TEST_F(TransportIntegrationTest, LoopbackDataTransfer) {
  auto now_fn = []() { return std::chrono::steady_clock::now(); };

  // Create UDP sockets.
  transport::UdpSocket client_socket;
  transport::UdpSocket server_socket;

  std::error_code ec;
  ASSERT_TRUE(server_socket.open(0, false, ec)) << ec.message();
  ASSERT_TRUE(client_socket.open(0, false, ec)) << ec.message();

  // Get the server's bound port (ephemeral port).
  // Since we can't easily get it, use a fixed port for testing.
  // For real tests, we'd need to expose the bound port.

  // Create transport sessions.
  transport::TransportSession client_session(client_handshake_, {}, now_fn);
  transport::TransportSession server_session(server_handshake_, {}, now_fn);

  // Encrypt data on client side.
  std::vector<std::uint8_t> plaintext{'H', 'e', 'l', 'l', 'o', ' ', 'V', 'E', 'I', 'L', '!'};
  auto encrypted_packets = client_session.encrypt_data(plaintext, 0, false);
  ASSERT_EQ(encrypted_packets.size(), 1U);

  // Simulate network transfer (in-memory for this test).
  for (const auto& pkt : encrypted_packets) {
    auto decrypted = server_session.decrypt_packet(pkt);
    ASSERT_TRUE(decrypted.has_value());
    ASSERT_EQ(decrypted->size(), 1U);
    EXPECT_EQ((*decrypted)[0].data.payload, plaintext);
  }

  // Test bidirectional communication.
  std::vector<std::uint8_t> response{'A', 'C', 'K'};
  auto response_packets = server_session.encrypt_data(response, 0, false);
  ASSERT_EQ(response_packets.size(), 1U);

  for (const auto& pkt : response_packets) {
    auto decrypted = client_session.decrypt_packet(pkt);
    ASSERT_TRUE(decrypted.has_value());
    ASSERT_EQ(decrypted->size(), 1U);
    EXPECT_EQ((*decrypted)[0].data.payload, response);
  }
}

// Test fragmentation with larger data.
TEST_F(TransportIntegrationTest, FragmentedDataTransfer) {
  auto now_fn = []() { return std::chrono::steady_clock::now(); };

  transport::TransportSessionConfig config;
  config.max_fragment_size = 50;  // Small fragments for testing

  transport::TransportSession client_session(client_handshake_, config, now_fn);
  transport::TransportSession server_session(server_handshake_, config, now_fn);

  // Create data that will be fragmented.
  std::vector<std::uint8_t> plaintext(150);
  for (std::size_t i = 0; i < plaintext.size(); ++i) {
    plaintext[i] = static_cast<std::uint8_t>(i & 0xFF);
  }

  auto encrypted_packets = client_session.encrypt_data(plaintext, 0, true);
  EXPECT_GE(encrypted_packets.size(), 2U) << "Expected fragmentation";

  // Decrypt all fragments on server side.
  std::vector<std::uint8_t> reassembled;
  for (const auto& pkt : encrypted_packets) {
    auto decrypted = server_session.decrypt_packet(pkt);
    ASSERT_TRUE(decrypted.has_value()) << "Failed to decrypt fragment";
    for (const auto& frame : *decrypted) {
      if (frame.kind == mux::FrameKind::kData) {
        reassembled.insert(reassembled.end(), frame.data.payload.begin(),
                           frame.data.payload.end());
      }
    }
  }

  EXPECT_EQ(reassembled, plaintext);
}

// Test out-of-order packet handling.
TEST_F(TransportIntegrationTest, OutOfOrderPackets) {
  auto now_fn = []() { return std::chrono::steady_clock::now(); };

  transport::TransportSession client_session(client_handshake_, {}, now_fn);
  transport::TransportSession server_session(server_handshake_, {}, now_fn);

  // Send multiple packets.
  std::vector<std::vector<std::uint8_t>> encrypted_packets;
  for (int i = 0; i < 5; ++i) {
    std::vector<std::uint8_t> data{static_cast<std::uint8_t>('A' + i)};
    auto pkts = client_session.encrypt_data(data, 0, false);
    encrypted_packets.insert(encrypted_packets.end(), pkts.begin(), pkts.end());
  }

  ASSERT_EQ(encrypted_packets.size(), 5U);

  // Deliver packets 0, 2, 4, 1, 3 (out of order).
  std::vector<std::size_t> order = {0, 2, 4, 1, 3};
  for (auto idx : order) {
    auto decrypted = server_session.decrypt_packet(encrypted_packets[idx]);
    EXPECT_TRUE(decrypted.has_value()) << "Failed to decrypt packet " << idx;
  }

  // All packets should be received.
  EXPECT_EQ(server_session.stats().packets_received, 5U);
}

// Test session rotation.
TEST_F(TransportIntegrationTest, SessionRotation) {
  std::chrono::steady_clock::time_point test_now = std::chrono::steady_clock::now();
  auto now_fn = [&test_now]() { return test_now; };

  transport::TransportSessionConfig config;
  config.session_rotation_interval = std::chrono::seconds(1);  // Short for testing
  config.session_rotation_packets = 1000000;

  transport::TransportSession client_session(client_handshake_, config, now_fn);
  transport::TransportSession server_session(server_handshake_, config, now_fn);

  auto initial_client_id = client_session.session_id();
  auto initial_server_id = server_session.session_id();

  // Exchange some data.
  std::vector<std::uint8_t> data{'T', 'e', 's', 't'};
  auto encrypted = client_session.encrypt_data(data, 0, false);
  for (const auto& pkt : encrypted) {
    server_session.decrypt_packet(pkt);
  }

  // Advance time past rotation interval.
  test_now += std::chrono::seconds(2);

  EXPECT_TRUE(client_session.should_rotate_session());
  client_session.rotate_session();
  EXPECT_NE(client_session.session_id(), initial_client_id);

  server_session.rotate_session();
  EXPECT_NE(server_session.session_id(), initial_server_id);

  EXPECT_EQ(client_session.stats().session_rotations, 1U);
  EXPECT_EQ(server_session.stats().session_rotations, 1U);
}

// Test ACK generation and processing.
TEST_F(TransportIntegrationTest, AckExchange) {
  auto now_fn = []() { return std::chrono::steady_clock::now(); };

  transport::TransportSession client_session(client_handshake_, {}, now_fn);
  transport::TransportSession server_session(server_handshake_, {}, now_fn);

  // Client sends multiple packets.
  for (int i = 0; i < 10; ++i) {
    std::vector<std::uint8_t> data{static_cast<std::uint8_t>(i)};
    auto encrypted = client_session.encrypt_data(data, 0, false);
    for (const auto& pkt : encrypted) {
      server_session.decrypt_packet(pkt);
    }
  }

  // Server generates ACK.
  auto ack = server_session.generate_ack(0);
  EXPECT_GT(ack.ack, 0U);

  // Client processes ACK.
  client_session.process_ack(ack);

  // Stats should reflect the exchange.
  EXPECT_EQ(server_session.stats().packets_received, 10U);
}

// Netem test (skipped if netem is not available).
TEST_F(TransportIntegrationTest, DISABLED_WithNetemDelay) {
  if (!is_netem_available()) {
    GTEST_SKIP() << "netem not available (requires root or VEIL_SKIP_NETEM is set)";
  }

  // Setup: tc qdisc add dev lo root netem delay 50ms 10ms
  // This would add 50ms delay with 10ms jitter on loopback.
  // For CI, we skip this test as it requires root privileges.

  auto now_fn = []() { return std::chrono::steady_clock::now(); };

  transport::TransportSession client_session(client_handshake_, {}, now_fn);
  transport::TransportSession server_session(server_handshake_, {}, now_fn);

  // This test would use real UDP sockets with netem-affected loopback.
  // The test verifies that the transport layer handles delays correctly.

  std::vector<std::uint8_t> data{'n', 'e', 't', 'e', 'm'};
  auto encrypted = client_session.encrypt_data(data, 0, false);

  // In a real test with sockets:
  // 1. Send encrypted packet over UDP
  // 2. Wait for delayed arrival
  // 3. Verify decryption succeeds

  EXPECT_FALSE(encrypted.empty());
}

// Test statistics tracking.
TEST_F(TransportIntegrationTest, StatisticsAccuracy) {
  auto now_fn = []() { return std::chrono::steady_clock::now(); };

  transport::TransportSession client_session(client_handshake_, {}, now_fn);
  transport::TransportSession server_session(server_handshake_, {}, now_fn);

  const std::size_t num_packets = 20;
  std::size_t total_payload_bytes = 0;

  for (std::size_t i = 0; i < num_packets; ++i) {
    std::vector<std::uint8_t> data(10 + i, static_cast<std::uint8_t>(i));
    total_payload_bytes += data.size();
    auto encrypted = client_session.encrypt_data(data, 0, false);
    for (const auto& pkt : encrypted) {
      server_session.decrypt_packet(pkt);
    }
  }

  const auto& client_stats = client_session.stats();
  const auto& server_stats = server_session.stats();

  EXPECT_EQ(client_stats.packets_sent, num_packets);
  EXPECT_GT(client_stats.bytes_sent, total_payload_bytes);  // Overhead

  EXPECT_EQ(server_stats.packets_received, num_packets);
  EXPECT_GT(server_stats.bytes_received, total_payload_bytes);  // Overhead

  EXPECT_EQ(server_stats.packets_dropped_replay, 0U);
  EXPECT_EQ(server_stats.packets_dropped_decrypt, 0U);
}

// Test replay attack detection across multiple exchanges.
TEST_F(TransportIntegrationTest, ReplayAttackDetection) {
  auto now_fn = []() { return std::chrono::steady_clock::now(); };

  transport::TransportSession client_session(client_handshake_, {}, now_fn);
  transport::TransportSession server_session(server_handshake_, {}, now_fn);

  // Send legitimate packets.
  std::vector<std::vector<std::uint8_t>> captured_packets;
  for (int i = 0; i < 5; ++i) {
    std::vector<std::uint8_t> data{static_cast<std::uint8_t>(i)};
    auto encrypted = client_session.encrypt_data(data, 0, false);
    captured_packets.insert(captured_packets.end(), encrypted.begin(), encrypted.end());

    for (const auto& pkt : encrypted) {
      auto result = server_session.decrypt_packet(pkt);
      EXPECT_TRUE(result.has_value());
    }
  }

  // Attempt replay attacks.
  for (const auto& pkt : captured_packets) {
    auto result = server_session.decrypt_packet(pkt);
    EXPECT_FALSE(result.has_value()) << "Replay attack should be detected";
  }

  EXPECT_EQ(server_session.stats().packets_dropped_replay, captured_packets.size());
}

}  // namespace veil::integration_tests
