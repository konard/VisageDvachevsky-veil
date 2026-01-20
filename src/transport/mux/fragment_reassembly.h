#pragma once

#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <vector>

namespace veil::mux {

struct Fragment {
  std::uint16_t offset{0};
  std::vector<std::uint8_t> data;
  bool last{false};
};

class FragmentReassembly {
 public:
  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;

  explicit FragmentReassembly(std::size_t max_bytes = 1 << 20,
                              std::chrono::milliseconds fragment_timeout =
                                  std::chrono::milliseconds(5000));

  bool push(std::uint64_t message_id, Fragment fragment,
            TimePoint now = Clock::now());

  std::optional<std::vector<std::uint8_t>> try_reassemble(std::uint64_t message_id);

  // Remove fragments that have exceeded the timeout.
  // Returns number of incomplete messages dropped.
  std::size_t cleanup_expired(TimePoint now = Clock::now());

  // Get number of incomplete messages currently buffered.
  [[nodiscard]] std::size_t pending_count() const { return state_.size(); }

  // Get total memory used by incomplete fragments.
  [[nodiscard]] std::size_t memory_usage() const;

 private:
  struct State {
    std::vector<Fragment> fragments;
    std::size_t total_bytes{0};
    bool has_last{false};
    TimePoint first_fragment_time{};
  };

  std::size_t max_bytes_;
  std::chrono::milliseconds fragment_timeout_;
  std::map<std::uint64_t, State> state_;
};

}  // namespace veil::mux
