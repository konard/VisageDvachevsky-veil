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

}  // namespace veil::tests
