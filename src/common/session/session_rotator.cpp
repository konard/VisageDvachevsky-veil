#include "common/session/session_rotator.h"

#include <chrono>
#include <cstdint>

#include "common/crypto/random.h"

namespace veil::session {

SessionRotator::SessionRotator(std::chrono::seconds interval, std::uint64_t max_packets)
    : interval_(interval),
      max_packets_(max_packets),
      session_id_(crypto::random_uint64()),
      last_rotation_(std::chrono::steady_clock::now()) {}

bool SessionRotator::should_rotate(std::uint64_t sent_packets,
                                   std::chrono::steady_clock::time_point now) const {
  const bool too_many_packets = sent_packets >= max_packets_;
  const bool expired = (now - last_rotation_) >= interval_;
  return too_many_packets || expired;
}

std::uint64_t SessionRotator::rotate(std::chrono::steady_clock::time_point now) {
  std::uint64_t next = crypto::random_uint64();
  if (next == session_id_) {
    next = crypto::random_uint64();
  }
  session_id_ = next;
  last_rotation_ = now;
  return session_id_;
}

}  // namespace veil::session
