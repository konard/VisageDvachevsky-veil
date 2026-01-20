#pragma once

#include <chrono>
#include <cstdint>

namespace veil::session {

class SessionRotator {
 public:
  SessionRotator(std::chrono::seconds interval, std::uint64_t max_packets);

  std::uint64_t current() const { return session_id_; }
  bool should_rotate(std::uint64_t sent_packets, std::chrono::steady_clock::time_point now) const;
  std::uint64_t rotate(std::chrono::steady_clock::time_point now);

 private:
  std::chrono::seconds interval_;
  std::uint64_t max_packets_;
  std::uint64_t session_id_;
  std::chrono::steady_clock::time_point last_rotation_;
};

}  // namespace veil::session
