#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <thread>
#include <vector>

#include "common/handshake/handshake_processor.h"
#include "common/utils/rate_limiter.h"

namespace veil::integration_tests {

using Clock = std::chrono::system_clock;

TEST(HandshakeIntegration, RoundTripWithSimulatedDelay) {
  Clock::time_point now = Clock::now();
  auto now_fn = [&]() { return now; };
  std::chrono::steady_clock::time_point steady_now = std::chrono::steady_clock::now();
  auto steady_fn = [&]() { return steady_now; };

  std::vector<std::uint8_t> psk(32, 0xAB);
  handshake::HandshakeInitiator initiator(psk, std::chrono::milliseconds(200), now_fn);
  utils::TokenBucket bucket(5.0, std::chrono::milliseconds(1000), steady_fn);
  handshake::HandshakeResponder responder(psk, std::chrono::milliseconds(200), std::move(bucket),
                                          now_fn);

  const auto init_bytes = initiator.create_init();
  now += std::chrono::milliseconds(50);  // emulate RTT/processing
  steady_now += std::chrono::milliseconds(50);
  auto resp = responder.handle_init(init_bytes);
  ASSERT_TRUE(resp.has_value());

  now += std::chrono::milliseconds(50);
  steady_now += std::chrono::milliseconds(50);
  auto session = initiator.consume_response(resp->response);
  ASSERT_TRUE(session.has_value());
  EXPECT_EQ(session->session_id, resp->session.session_id);
}

TEST(HandshakeIntegration, RateLimiterBlocksBurst) {
  Clock::time_point now = Clock::now();
  auto now_fn = [&]() { return now; };
  std::chrono::steady_clock::time_point steady_now = std::chrono::steady_clock::now();
  auto steady_fn = [&]() { return steady_now; };

  std::vector<std::uint8_t> psk(32, 0xCD);
  utils::TokenBucket bucket(1.0, std::chrono::milliseconds(1000), steady_fn);
  handshake::HandshakeResponder responder(psk, std::chrono::milliseconds(500), std::move(bucket),
                                          now_fn);
  handshake::HandshakeInitiator initiator(psk, std::chrono::milliseconds(500), now_fn);

  const auto init1 = initiator.create_init();
  auto r1 = responder.handle_init(init1);
  auto r2 = responder.handle_init(init1);
  EXPECT_TRUE(r1.has_value());
  EXPECT_FALSE(r2.has_value());

  now += std::chrono::milliseconds(1001);
  steady_now += std::chrono::milliseconds(1001);
  const auto init2 = initiator.create_init();
  auto r3 = responder.handle_init(init2);
  EXPECT_TRUE(r3.has_value());
}

}  // namespace veil::integration_tests
