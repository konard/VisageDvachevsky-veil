#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <vector>

#include "common/crypto/crypto_engine.h"
#include "common/handshake/handshake_replay_cache.h"
#include "common/utils/rate_limiter.h"

namespace veil::handshake {

enum class MessageType : std::uint8_t { kInit = 1, kResponse = 2 };

struct HandshakeSession {
  std::uint64_t session_id;
  crypto::SessionKeys keys;
  std::array<std::uint8_t, crypto::kX25519PublicKeySize> initiator_ephemeral;
  std::array<std::uint8_t, crypto::kX25519PublicKeySize> responder_ephemeral;
};

class HandshakeInitiator {
 public:
  using Clock = std::chrono::system_clock;
  HandshakeInitiator(std::vector<std::uint8_t> psk, std::chrono::milliseconds skew_tolerance,
                     std::function<Clock::time_point()> now_fn = Clock::now);

  /// SECURITY: Destructor clears all sensitive key material
  ~HandshakeInitiator();

  // Disable copy (contains sensitive data)
  HandshakeInitiator(const HandshakeInitiator&) = delete;
  HandshakeInitiator& operator=(const HandshakeInitiator&) = delete;

  // Enable move
  HandshakeInitiator(HandshakeInitiator&&) = default;
  HandshakeInitiator& operator=(HandshakeInitiator&&) = default;

  std::vector<std::uint8_t> create_init();
  std::optional<HandshakeSession> consume_response(std::span<const std::uint8_t> response);

 private:
  std::vector<std::uint8_t> psk_;
  std::chrono::milliseconds skew_tolerance_;
  std::function<Clock::time_point()> now_fn_;

  crypto::KeyPair ephemeral_;
  std::uint64_t init_timestamp_ms_{0};
  bool init_sent_{false};
};

class HandshakeResponder {
 public:
  using Clock = std::chrono::system_clock;
  struct Result {
    std::vector<std::uint8_t> response;
    HandshakeSession session;
  };

  HandshakeResponder(std::vector<std::uint8_t> psk, std::chrono::milliseconds skew_tolerance,
                     utils::TokenBucket rate_limiter,
                     std::function<Clock::time_point()> now_fn = Clock::now);

  /// SECURITY: Destructor clears all sensitive key material
  ~HandshakeResponder();

  // Disable copy (contains sensitive data)
  HandshakeResponder(const HandshakeResponder&) = delete;
  HandshakeResponder& operator=(const HandshakeResponder&) = delete;

  // Disable move (contains non-movable replay cache with mutex)
  HandshakeResponder(HandshakeResponder&&) = delete;
  HandshakeResponder& operator=(HandshakeResponder&&) = delete;

  std::optional<Result> handle_init(std::span<const std::uint8_t> init_bytes);

 private:
  std::vector<std::uint8_t> psk_;
  std::chrono::milliseconds skew_tolerance_;
  utils::TokenBucket rate_limiter_;
  HandshakeReplayCache replay_cache_;
  std::function<Clock::time_point()> now_fn_;
};

}  // namespace veil::handshake
