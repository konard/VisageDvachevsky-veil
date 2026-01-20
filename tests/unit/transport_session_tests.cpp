#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <vector>

#include "common/handshake/handshake_processor.h"
#include "common/utils/rate_limiter.h"
#include "transport/session/transport_session.h"

namespace veil::tests {

using namespace std::chrono_literals;

class TransportSessionTest : public ::testing::Test {
 protected:
  void SetUp() override {
    now_ = std::chrono::system_clock::now();
    steady_now_ = std::chrono::steady_clock::now();

    auto now_fn = [this]() { return now_; };
    auto steady_fn = [this]() { return steady_now_; };

    psk_ = std::vector<std::uint8_t>(32, 0xAB);

    // Perform handshake to get session.
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

TEST_F(TransportSessionTest, EncryptDecryptRoundTrip) {
  auto client_now_fn = [this]() { return steady_now_; };
  auto server_now_fn = [this]() { return steady_now_; };

  transport::TransportSession client(client_handshake_, {}, client_now_fn);
  transport::TransportSession server(server_handshake_, {}, server_now_fn);

  std::vector<std::uint8_t> plaintext{0x01, 0x02, 0x03, 0x04, 0x05};
  auto encrypted_packets = client.encrypt_data(plaintext, 0, false);
  ASSERT_EQ(encrypted_packets.size(), 1U);

  auto decrypted_frames = server.decrypt_packet(encrypted_packets[0]);
  ASSERT_TRUE(decrypted_frames.has_value());
  ASSERT_EQ(decrypted_frames->size(), 1U);
  EXPECT_EQ((*decrypted_frames)[0].kind, mux::FrameKind::kData);
  EXPECT_EQ((*decrypted_frames)[0].data.payload, plaintext);
}

TEST_F(TransportSessionTest, ReplayProtection) {
  auto now_fn = [this]() { return steady_now_; };

  transport::TransportSession client(client_handshake_, {}, now_fn);
  transport::TransportSession server(server_handshake_, {}, now_fn);

  std::vector<std::uint8_t> plaintext{0x01, 0x02};
  auto encrypted_packets = client.encrypt_data(plaintext, 0, false);
  ASSERT_EQ(encrypted_packets.size(), 1U);

  // First decryption should succeed.
  auto decrypted1 = server.decrypt_packet(encrypted_packets[0]);
  ASSERT_TRUE(decrypted1.has_value());

  // Replay should be rejected.
  auto decrypted2 = server.decrypt_packet(encrypted_packets[0]);
  EXPECT_FALSE(decrypted2.has_value());
  EXPECT_EQ(server.stats().packets_dropped_replay, 1U);
}

TEST_F(TransportSessionTest, TamperedPacketRejected) {
  auto now_fn = [this]() { return steady_now_; };

  transport::TransportSession client(client_handshake_, {}, now_fn);
  transport::TransportSession server(server_handshake_, {}, now_fn);

  std::vector<std::uint8_t> plaintext{0x01, 0x02, 0x03};
  auto encrypted_packets = client.encrypt_data(plaintext, 0, false);
  ASSERT_EQ(encrypted_packets.size(), 1U);

  // Tamper with the ciphertext.
  encrypted_packets[0][10] ^= 0xFF;

  auto decrypted = server.decrypt_packet(encrypted_packets[0]);
  EXPECT_FALSE(decrypted.has_value());
  EXPECT_EQ(server.stats().packets_dropped_decrypt, 1U);
}

TEST_F(TransportSessionTest, SequenceIncrements) {
  auto now_fn = [this]() { return steady_now_; };

  transport::TransportSession client(client_handshake_, {}, now_fn);

  EXPECT_EQ(client.send_sequence(), 0U);

  std::vector<std::uint8_t> data1{0x01};
  client.encrypt_data(data1, 0, false);
  EXPECT_EQ(client.send_sequence(), 1U);

  std::vector<std::uint8_t> data2{0x02};
  client.encrypt_data(data2, 0, false);
  EXPECT_EQ(client.send_sequence(), 2U);
}

TEST_F(TransportSessionTest, AckGeneration) {
  auto client_now_fn = [this]() { return steady_now_; };
  auto server_now_fn = [this]() { return steady_now_; };

  transport::TransportSession client(client_handshake_, {}, client_now_fn);
  transport::TransportSession server(server_handshake_, {}, server_now_fn);

  // Send multiple packets.
  for (int i = 0; i < 5; ++i) {
    std::vector<std::uint8_t> data{static_cast<std::uint8_t>(i)};
    auto packets = client.encrypt_data(data, 0, false);
    for (const auto& pkt : packets) {
      server.decrypt_packet(pkt);
    }
  }

  // Generate ACK.
  auto ack = server.generate_ack(0);
  EXPECT_GT(ack.ack, 0U);
}

TEST_F(TransportSessionTest, Fragmentation) {
  auto now_fn = [this]() { return steady_now_; };

  transport::TransportSessionConfig config;
  config.max_fragment_size = 10;  // Very small to force fragmentation

  transport::TransportSession client(client_handshake_, config, now_fn);
  transport::TransportSession server(server_handshake_, config, now_fn);

  // Create data larger than max_fragment_size.
  std::vector<std::uint8_t> plaintext(25);
  for (std::size_t i = 0; i < plaintext.size(); ++i) {
    plaintext[i] = static_cast<std::uint8_t>(i);
  }

  auto encrypted_packets = client.encrypt_data(plaintext, 0, true);
  EXPECT_GE(encrypted_packets.size(), 2U);  // Should be fragmented

  EXPECT_EQ(client.stats().fragments_sent, encrypted_packets.size());

  // Decrypt all fragments.
  for (const auto& pkt : encrypted_packets) {
    auto decrypted = server.decrypt_packet(pkt);
    ASSERT_TRUE(decrypted.has_value());
  }
}

TEST_F(TransportSessionTest, SessionRotation) {
  auto now_fn = [this]() { return steady_now_; };

  transport::TransportSessionConfig config;
  config.session_rotation_interval = std::chrono::seconds(1);
  config.session_rotation_packets = 1000000;

  transport::TransportSession session(client_handshake_, config, now_fn);

  auto initial_id = session.session_id();
  EXPECT_FALSE(session.should_rotate_session());

  // Advance time past rotation interval.
  steady_now_ += std::chrono::seconds(2);
  EXPECT_TRUE(session.should_rotate_session());

  session.rotate_session();
  EXPECT_NE(session.session_id(), initial_id);
  EXPECT_EQ(session.stats().session_rotations, 1U);
}

TEST_F(TransportSessionTest, Stats) {
  auto now_fn = [this]() { return steady_now_; };

  transport::TransportSession client(client_handshake_, {}, now_fn);
  transport::TransportSession server(server_handshake_, {}, now_fn);

  std::vector<std::uint8_t> plaintext{0x01, 0x02, 0x03};
  auto packets = client.encrypt_data(plaintext, 0, false);

  EXPECT_EQ(client.stats().packets_sent, 1U);
  EXPECT_GT(client.stats().bytes_sent, 0U);

  for (const auto& pkt : packets) {
    server.decrypt_packet(pkt);
  }

  EXPECT_EQ(server.stats().packets_received, 1U);
  EXPECT_GT(server.stats().bytes_received, 0U);
}

TEST_F(TransportSessionTest, SmallPacketRejected) {
  auto now_fn = [this]() { return steady_now_; };
  transport::TransportSession server(server_handshake_, {}, now_fn);

  // Packet too small (less than minimum required).
  std::vector<std::uint8_t> small_packet{0x01, 0x02, 0x03};
  auto result = server.decrypt_packet(small_packet);
  EXPECT_FALSE(result.has_value());
}

}  // namespace veil::tests
