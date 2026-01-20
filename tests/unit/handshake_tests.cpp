#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <optional>
#include <vector>

#include "common/handshake/handshake_processor.h"
#include "common/utils/rate_limiter.h"

namespace veil::tests {

namespace {
std::vector<std::uint8_t> make_psk() { return std::vector<std::uint8_t>(32, 0xAA); }
}

TEST(HandshakeTests, SuccessfulHandshakeProducesMatchingKeys) {
  auto now = std::chrono::system_clock::now();
  auto now_fn = [&]() { return now; };

  handshake::HandshakeInitiator initiator(make_psk(), std::chrono::milliseconds(1000), now_fn);
  utils::TokenBucket bucket(10.0, std::chrono::milliseconds(1000), [] {
    return std::chrono::steady_clock::now();
  });
  handshake::HandshakeResponder responder(make_psk(), std::chrono::milliseconds(1000),
                                          std::move(bucket), now_fn);

  const auto init_bytes = initiator.create_init();
  auto resp = responder.handle_init(init_bytes);
  ASSERT_TRUE(resp.has_value());

  auto session = initiator.consume_response(resp->response);
  ASSERT_TRUE(session.has_value());
  EXPECT_EQ(session->session_id, resp->session.session_id);
  EXPECT_EQ(session->keys.send_key, resp->session.keys.recv_key);
  EXPECT_EQ(session->keys.recv_key, resp->session.keys.send_key);
  EXPECT_EQ(session->keys.send_nonce, resp->session.keys.recv_nonce);
  EXPECT_EQ(session->keys.recv_nonce, resp->session.keys.send_nonce);
}

TEST(HandshakeTests, InvalidHmacSilentlyDropped) {
  auto now = std::chrono::system_clock::now();
  auto now_fn = [&]() { return now; };

  handshake::HandshakeInitiator initiator(make_psk(), std::chrono::milliseconds(1000), now_fn);
  utils::TokenBucket bucket(1.0, std::chrono::milliseconds(1000), [] {
    return std::chrono::steady_clock::now();
  });
  handshake::HandshakeResponder responder(make_psk(), std::chrono::milliseconds(1000),
                                          std::move(bucket), now_fn);

  auto init_bytes = initiator.create_init();
  init_bytes.back() ^= 0x01;
  auto resp = responder.handle_init(init_bytes);
  EXPECT_FALSE(resp.has_value());
}

TEST(HandshakeTests, TimestampOutsideWindowDropped) {
  auto now = std::chrono::system_clock::now();
  auto now_fn_future = [&]() { return now + std::chrono::seconds(10); };
  auto now_fn_past = [&]() { return now; };

  handshake::HandshakeInitiator initiator(make_psk(), std::chrono::milliseconds(1000), now_fn_future);
  utils::TokenBucket bucket(1.0, std::chrono::milliseconds(1000), [] {
    return std::chrono::steady_clock::now();
  });
  handshake::HandshakeResponder responder(make_psk(), std::chrono::milliseconds(1000),
                                          std::move(bucket), now_fn_past);

  const auto init_bytes = initiator.create_init();
  auto resp = responder.handle_init(init_bytes);
  EXPECT_FALSE(resp.has_value());
}

TEST(HandshakeTests, RateLimiterDropsExcess) {
  auto now = std::chrono::system_clock::now();
  auto now_fn = [&]() { return now; };

  handshake::HandshakeInitiator initiator(make_psk(), std::chrono::milliseconds(1000), now_fn);
  utils::TokenBucket bucket(1.0, std::chrono::milliseconds(1000), [] {
    return std::chrono::steady_clock::now();
  });
  handshake::HandshakeResponder responder(make_psk(), std::chrono::milliseconds(1000),
                                          bucket, now_fn);

  const auto init_bytes = initiator.create_init();
  auto first = responder.handle_init(init_bytes);
  auto second = responder.handle_init(init_bytes);
  EXPECT_TRUE(first.has_value());
  EXPECT_FALSE(second.has_value());
}

// DPI Resistance Tests - Issue #19
// Verifies that encrypted handshake packets don't contain detectable signatures

TEST(HandshakeTests, InitPacketDoesNotContainPlaintextMagicBytes) {
  auto now = std::chrono::system_clock::now();
  auto now_fn = [&]() { return now; };

  handshake::HandshakeInitiator initiator(make_psk(), std::chrono::milliseconds(1000), now_fn);
  const auto init_bytes = initiator.create_init();

  // Check that the plaintext "HS" magic bytes are NOT present in the encrypted packet
  // The magic bytes would be 0x48, 0x53 ('H', 'S')
  bool found_magic = false;
  for (std::size_t i = 0; i + 1 < init_bytes.size(); ++i) {
    if (init_bytes[i] == 0x48 && init_bytes[i + 1] == 0x53) {
      found_magic = true;
      break;
    }
  }
  EXPECT_FALSE(found_magic) << "Plaintext magic bytes 'HS' found in encrypted handshake packet";

  // The encrypted packet should be larger due to nonce (12 bytes), AEAD tag (16 bytes), and padding
  // Original INIT size: 2 + 1 + 1 + 8 + 32 + 32 = 76 bytes
  // With padding: 76 + 2 (padding length) + 32-400 (padding) = 110-478 bytes
  // Encrypted size: 12 (nonce) + plaintext + 16 (tag) = 138-506 bytes
  // Verify size is within expected range
  EXPECT_GE(init_bytes.size(), 138u) << "Encrypted INIT packet should be at least 138 bytes";
  EXPECT_LE(init_bytes.size(), 506u) << "Encrypted INIT packet should be at most 506 bytes";
}

TEST(HandshakeTests, ResponsePacketDoesNotContainPlaintextMagicBytes) {
  auto now = std::chrono::system_clock::now();
  auto now_fn = [&]() { return now; };

  handshake::HandshakeInitiator initiator(make_psk(), std::chrono::milliseconds(1000), now_fn);
  utils::TokenBucket bucket(10.0, std::chrono::milliseconds(1000), [] {
    return std::chrono::steady_clock::now();
  });
  handshake::HandshakeResponder responder(make_psk(), std::chrono::milliseconds(1000),
                                          std::move(bucket), now_fn);

  const auto init_bytes = initiator.create_init();
  auto resp = responder.handle_init(init_bytes);
  ASSERT_TRUE(resp.has_value());

  const auto& response_bytes = resp->response;

  // Check that the plaintext "HS" magic bytes are NOT present in the response
  bool found_magic = false;
  for (std::size_t i = 0; i + 1 < response_bytes.size(); ++i) {
    if (response_bytes[i] == 0x48 && response_bytes[i + 1] == 0x53) {
      found_magic = true;
      break;
    }
  }
  EXPECT_FALSE(found_magic) << "Plaintext magic bytes 'HS' found in encrypted response packet";

  // Original RESPONSE size: 2 + 1 + 1 + 8 + 8 + 8 + 32 + 32 = 92 bytes
  // With padding: 92 + 2 (padding length) + 32-400 (padding) = 126-494 bytes
  // Encrypted size: 12 (nonce) + plaintext + 16 (tag) = 154-522 bytes
  // Verify size is within expected range
  EXPECT_GE(response_bytes.size(), 154u) << "Encrypted RESPONSE packet should be at least 154 bytes";
  EXPECT_LE(response_bytes.size(), 522u) << "Encrypted RESPONSE packet should be at most 522 bytes";
}

TEST(HandshakeTests, EncryptedPacketsAppearRandom) {
  auto now = std::chrono::system_clock::now();
  auto now_fn = [&]() { return now; };

  handshake::HandshakeInitiator initiator1(make_psk(), std::chrono::milliseconds(1000), now_fn);
  handshake::HandshakeInitiator initiator2(make_psk(), std::chrono::milliseconds(1000), now_fn);

  const auto init1 = initiator1.create_init();
  const auto init2 = initiator2.create_init();

  // Two handshake packets created with same PSK and timestamp should be different
  // due to random nonce and ephemeral keys
  EXPECT_NE(init1, init2) << "Handshake packets should be different due to random nonce";

  // Check that the first 12 bytes (nonce) are different
  bool nonce_differs = false;
  for (std::size_t i = 0; i < 12 && i < init1.size() && i < init2.size(); ++i) {
    if (init1[i] != init2[i]) {
      nonce_differs = true;
      break;
    }
  }
  EXPECT_TRUE(nonce_differs) << "Nonces should differ between packets";
}

TEST(HandshakeTests, WrongPskCannotDecrypt) {
  auto now = std::chrono::system_clock::now();
  auto now_fn = [&]() { return now; };

  std::vector<std::uint8_t> psk1(32, 0xAA);
  std::vector<std::uint8_t> psk2(32, 0xBB);

  handshake::HandshakeInitiator initiator(psk1, std::chrono::milliseconds(1000), now_fn);
  utils::TokenBucket bucket(10.0, std::chrono::milliseconds(1000), [] {
    return std::chrono::steady_clock::now();
  });
  handshake::HandshakeResponder responder(psk2, std::chrono::milliseconds(1000),
                                          std::move(bucket), now_fn);

  const auto init_bytes = initiator.create_init();
  auto resp = responder.handle_init(init_bytes);

  // Should fail because wrong PSK cannot decrypt the handshake
  EXPECT_FALSE(resp.has_value()) << "Decryption should fail with wrong PSK";
}

}  // namespace veil::tests
