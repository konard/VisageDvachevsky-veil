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

// =============================================================================
// NONCE LIFECYCLE TESTS (Issue #3)
// These tests verify the security-critical property that nonce counters are
// never reset, ensuring nonce uniqueness across session rotations.
// =============================================================================

TEST_F(TransportSessionTest, SendSequenceContinuesAfterSessionRotation) {
  // Verifies that send_sequence_ is NOT reset during session rotation.
  // This is critical for nonce uniqueness: nonce = derive_nonce(base_nonce, send_sequence_)
  // If send_sequence_ were reset, we'd reuse nonces with the same key, breaking security.
  auto now_fn = [this]() { return steady_now_; };

  transport::TransportSessionConfig config;
  config.session_rotation_interval = std::chrono::seconds(1);
  config.session_rotation_packets = 1000000;

  transport::TransportSession client(client_handshake_, config, now_fn);

  // Send some packets before rotation
  const std::uint64_t packets_before_rotation = 10;
  for (std::uint64_t i = 0; i < packets_before_rotation; ++i) {
    std::vector<std::uint8_t> data{static_cast<std::uint8_t>(i)};
    client.encrypt_data(data, 0, false);
  }

  std::uint64_t sequence_before_rotation = client.send_sequence();
  EXPECT_EQ(sequence_before_rotation, packets_before_rotation);

  // Trigger session rotation
  steady_now_ += std::chrono::seconds(2);
  EXPECT_TRUE(client.should_rotate_session());
  client.rotate_session();

  // CRITICAL ASSERTION: send_sequence must NOT be reset
  std::uint64_t sequence_after_rotation = client.send_sequence();
  EXPECT_EQ(sequence_after_rotation, sequence_before_rotation)
      << "send_sequence_ must NOT reset after session rotation to prevent nonce reuse";

  // Send more packets after rotation
  const std::uint64_t packets_after_rotation = 5;
  for (std::uint64_t i = 0; i < packets_after_rotation; ++i) {
    std::vector<std::uint8_t> data{static_cast<std::uint8_t>(i + 100)};
    client.encrypt_data(data, 0, false);
  }

  // Verify sequence continues monotonically
  EXPECT_EQ(client.send_sequence(), packets_before_rotation + packets_after_rotation)
      << "send_sequence_ must continue incrementing after rotation";
}

TEST_F(TransportSessionTest, NonceUniquenessAcrossMultipleRotations) {
  // Verifies nonces are unique even after multiple session rotations.
  // This test collects all sequence numbers used across rotations and
  // verifies they are all unique.
  auto now_fn = [this]() { return steady_now_; };

  transport::TransportSessionConfig config;
  config.session_rotation_interval = std::chrono::seconds(1);
  config.session_rotation_packets = 1000000;

  transport::TransportSession client(client_handshake_, config, now_fn);

  std::vector<std::uint64_t> all_sequences;
  const int num_rotations = 3;
  const int packets_per_rotation = 5;

  for (int rotation = 0; rotation <= num_rotations; ++rotation) {
    // Record sequences before sending
    for (int pkt = 0; pkt < packets_per_rotation; ++pkt) {
      std::uint64_t seq_before = client.send_sequence();
      all_sequences.push_back(seq_before);

      std::vector<std::uint8_t> data{static_cast<std::uint8_t>(rotation * 10 + pkt)};
      client.encrypt_data(data, 0, false);
    }

    if (rotation < num_rotations) {
      // Trigger rotation
      steady_now_ += std::chrono::seconds(2);
      client.rotate_session();
    }
  }

  // Verify all sequences are unique
  std::vector<std::uint64_t> sorted_sequences = all_sequences;
  std::sort(sorted_sequences.begin(), sorted_sequences.end());

  for (std::size_t i = 1; i < sorted_sequences.size(); ++i) {
    EXPECT_NE(sorted_sequences[i], sorted_sequences[i - 1])
        << "Duplicate sequence number detected: " << sorted_sequences[i]
        << " - this would cause nonce reuse!";
  }

  // Verify sequences are strictly increasing (monotonic)
  for (std::size_t i = 1; i < all_sequences.size(); ++i) {
    EXPECT_GT(all_sequences[i], all_sequences[i - 1])
        << "Sequence numbers must be strictly increasing";
  }
}

TEST_F(TransportSessionTest, EncryptDecryptAcrossSessionRotations) {
  // End-to-end test verifying that packets encrypted before and after
  // session rotation can all be decrypted correctly by the peer.
  // This proves the nonce/key relationship is maintained correctly.
  auto client_now_fn = [this]() { return steady_now_; };
  auto server_now_fn = [this]() { return steady_now_; };

  transport::TransportSessionConfig config;
  config.session_rotation_interval = std::chrono::seconds(1);
  config.session_rotation_packets = 1000000;

  transport::TransportSession client(client_handshake_, config, client_now_fn);
  transport::TransportSession server(server_handshake_, config, server_now_fn);

  std::vector<std::vector<std::uint8_t>> all_encrypted;
  std::vector<std::vector<std::uint8_t>> expected_plaintexts;

  // Send packets before rotation
  for (int i = 0; i < 3; ++i) {
    std::vector<std::uint8_t> plaintext{0x10, static_cast<std::uint8_t>(i)};
    expected_plaintexts.push_back(plaintext);
    auto encrypted = client.encrypt_data(plaintext, 0, false);
    for (auto& pkt : encrypted) {
      all_encrypted.push_back(std::move(pkt));
    }
  }

  // Trigger rotation on client only (simulating real-world scenario)
  // Note: In real protocol, rotation would be coordinated, but for this test
  // we're verifying the crypto layer continues working
  steady_now_ += std::chrono::seconds(2);
  client.rotate_session();

  // Send packets after rotation
  for (int i = 0; i < 3; ++i) {
    std::vector<std::uint8_t> plaintext{0x20, static_cast<std::uint8_t>(i)};
    expected_plaintexts.push_back(plaintext);
    auto encrypted = client.encrypt_data(plaintext, 0, false);
    for (auto& pkt : encrypted) {
      all_encrypted.push_back(std::move(pkt));
    }
  }

  // Decrypt all packets - they should all succeed because:
  // 1. Keys haven't changed (session rotation changes session_id, not crypto keys)
  // 2. Nonces are all unique (send_sequence_ was not reset)
  for (std::size_t i = 0; i < all_encrypted.size(); ++i) {
    auto decrypted = server.decrypt_packet(all_encrypted[i]);
    ASSERT_TRUE(decrypted.has_value()) << "Failed to decrypt packet " << i;
    ASSERT_EQ(decrypted->size(), 1U);
    EXPECT_EQ((*decrypted)[0].data.payload, expected_plaintexts[i])
        << "Decrypted payload mismatch for packet " << i;
  }
}

TEST_F(TransportSessionTest, PacketCountBasedRotationPreservesSequence) {
  // Test rotation triggered by packet count threshold (not time)
  auto now_fn = [this]() { return steady_now_; };

  transport::TransportSessionConfig config;
  config.session_rotation_interval = std::chrono::hours(24);  // Very long, won't trigger
  config.session_rotation_packets = 5;  // Small threshold for testing

  transport::TransportSession client(client_handshake_, config, now_fn);

  auto initial_session_id = client.session_id();

  // Send packets until rotation should trigger
  for (int i = 0; i < 5; ++i) {
    std::vector<std::uint8_t> data{static_cast<std::uint8_t>(i)};
    client.encrypt_data(data, 0, false);
  }

  EXPECT_EQ(client.send_sequence(), 5U);
  EXPECT_TRUE(client.should_rotate_session());

  std::uint64_t sequence_before = client.send_sequence();
  client.rotate_session();
  std::uint64_t sequence_after = client.send_sequence();

  // Session ID should change
  EXPECT_NE(client.session_id(), initial_session_id);

  // But sequence should NOT reset
  EXPECT_EQ(sequence_after, sequence_before)
      << "Packet-count triggered rotation must not reset send_sequence_";

  // Continue sending - sequence should continue
  std::vector<std::uint8_t> data{0xFF};
  client.encrypt_data(data, 0, false);
  EXPECT_EQ(client.send_sequence(), 6U);
}

// =============================================================================
// SEQUENCE OBFUSCATION TESTS (Issue #21)
// These tests verify that sequence numbers are properly obfuscated to prevent
// DPI detection based on monotonically increasing plaintext sequences.
// =============================================================================

TEST_F(TransportSessionTest, SequenceNumbersAreObfuscatedInWireFormat) {
  // Verifies that the first 8 bytes of encrypted packets do NOT contain
  // the plaintext sequence number. This prevents DPI from detecting monotonic
  // sequences which would reveal encrypted tunnel usage.
  auto now_fn = [this]() { return steady_now_; };

  transport::TransportSession client(client_handshake_, {}, now_fn);

  // Send multiple packets and collect their wire representations
  std::vector<std::vector<std::uint8_t>> packets;
  for (int i = 0; i < 10; ++i) {
    std::vector<std::uint8_t> data{static_cast<std::uint8_t>(i)};
    auto encrypted = client.encrypt_data(data, 0, false);
    ASSERT_EQ(encrypted.size(), 1U);
    packets.push_back(encrypted[0]);
  }

  // Extract the first 8 bytes from each packet (the obfuscated sequence)
  std::vector<std::uint64_t> wire_sequences;
  for (const auto& pkt : packets) {
    ASSERT_GE(pkt.size(), 8U);
    std::uint64_t wire_seq = 0;
    for (int i = 0; i < 8; ++i) {
      wire_seq = (wire_seq << 8) | pkt[static_cast<std::size_t>(i)];
    }
    wire_sequences.push_back(wire_seq);
  }

  // Verify that wire sequences are NOT monotonically increasing
  // (i.e., they are properly obfuscated)
  bool is_monotonic = true;
  for (std::size_t i = 1; i < wire_sequences.size(); ++i) {
    if (wire_sequences[i] <= wire_sequences[i - 1]) {
      is_monotonic = false;
      break;
    }
  }

  EXPECT_FALSE(is_monotonic)
      << "Wire sequences appear monotonic, suggesting insufficient obfuscation";

  // Verify that consecutive sequences have large differences (high entropy)
  for (std::size_t i = 1; i < wire_sequences.size(); ++i) {
    std::int64_t diff = static_cast<std::int64_t>(wire_sequences[i]) -
                        static_cast<std::int64_t>(wire_sequences[i - 1]);
    // If obfuscation is working, differences should be large and unpredictable
    // For true randomness, we'd expect differences >> 1
    EXPECT_NE(std::abs(diff), 1)
        << "Consecutive obfuscated sequences differ by 1, suggesting weak obfuscation";
  }
}

TEST_F(TransportSessionTest, ObfuscatedPacketsStillDecryptCorrectly) {
  // Verifies that obfuscation doesn't break the decrypt path - the receiver
  // should still be able to deobfuscate and decrypt packets normally.
  auto client_now_fn = [this]() { return steady_now_; };
  auto server_now_fn = [this]() { return steady_now_; };

  transport::TransportSession client(client_handshake_, {}, client_now_fn);
  transport::TransportSession server(server_handshake_, {}, server_now_fn);

  // Send many packets to test obfuscation doesn't affect correctness
  for (std::size_t i = 0; i < 100; ++i) {
    std::vector<std::uint8_t> plaintext(100);
    for (std::size_t j = 0; j < plaintext.size(); ++j) {
      plaintext[j] = static_cast<std::uint8_t>((i + j) & 0xFF);
    }

    auto encrypted = client.encrypt_data(plaintext, 0, false);
    ASSERT_EQ(encrypted.size(), 1U);

    auto decrypted = server.decrypt_packet(encrypted[0]);
    ASSERT_TRUE(decrypted.has_value());
    ASSERT_EQ(decrypted->size(), 1U);
    EXPECT_EQ((*decrypted)[0].data.payload, plaintext);
  }

  // Verify all packets were received successfully
  EXPECT_EQ(server.stats().packets_received, 100U);
  EXPECT_EQ(server.stats().packets_dropped_decrypt, 0U);
  EXPECT_EQ(server.stats().packets_dropped_replay, 0U);
}

TEST_F(TransportSessionTest, DifferentSessionsProduceDifferentObfuscation) {
  // Verifies that different sessions (with different keys) produce different
  // obfuscated sequences, preventing correlation across sessions.
  auto now_fn_sys = [this]() { return now_; };
  auto now_fn_steady = [this]() { return steady_now_; };

  // Create two independent handshake sessions
  handshake::HandshakeInitiator initiator1(psk_, 200ms, now_fn_sys);
  handshake::HandshakeInitiator initiator2(psk_, 200ms, now_fn_sys);

  utils::TokenBucket bucket1(100.0, 1000ms, now_fn_steady);
  utils::TokenBucket bucket2(100.0, 1000ms, now_fn_steady);

  handshake::HandshakeResponder responder1(psk_, 200ms, std::move(bucket1), now_fn_sys);
  handshake::HandshakeResponder responder2(psk_, 200ms, std::move(bucket2), now_fn_sys);

  auto init1 = initiator1.create_init();
  now_ += 10ms;
  steady_now_ += 10ms;
  auto resp1 = responder1.handle_init(init1);
  ASSERT_TRUE(resp1.has_value());

  now_ += 10ms;
  steady_now_ += 10ms;
  auto init2 = initiator2.create_init();
  now_ += 10ms;
  steady_now_ += 10ms;
  auto resp2 = responder2.handle_init(init2);
  ASSERT_TRUE(resp2.has_value());

  now_ += 10ms;
  steady_now_ += 10ms;
  auto session1 = initiator1.consume_response(resp1->response);
  ASSERT_TRUE(session1.has_value());

  auto session2 = initiator2.consume_response(resp2->response);
  ASSERT_TRUE(session2.has_value());

  // Create transport sessions
  transport::TransportSession transport1(*session1, {}, now_fn_steady);
  transport::TransportSession transport2(*session2, {}, now_fn_steady);

  // Send first packet from both sessions
  std::vector<std::uint8_t> data{0x42};
  auto pkt1 = transport1.encrypt_data(data, 0, false);
  auto pkt2 = transport2.encrypt_data(data, 0, false);

  ASSERT_EQ(pkt1.size(), 1U);
  ASSERT_EQ(pkt2.size(), 1U);

  // Extract first 8 bytes (obfuscated sequence) from each
  std::uint64_t obf_seq1 = 0;
  std::uint64_t obf_seq2 = 0;

  for (int i = 0; i < 8; ++i) {
    obf_seq1 = (obf_seq1 << 8) | pkt1[0][static_cast<std::size_t>(i)];
    obf_seq2 = (obf_seq2 << 8) | pkt2[0][static_cast<std::size_t>(i)];
  }

  // Even though both sessions sent sequence 0, the obfuscated values should differ
  EXPECT_NE(obf_seq1, obf_seq2)
      << "Different sessions should produce different obfuscated sequences";
}

}  // namespace veil::tests
