#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace veil::session {

class ReplayWindow {
 public:
  explicit ReplayWindow(std::size_t window_size = 1024);
  bool mark_and_check(std::uint64_t sequence);

 private:
  std::size_t window_size_;
  std::uint64_t highest_{0};
  bool initialized_{false};
  std::vector<std::uint64_t> bits_;

  void shift(std::size_t delta);
  bool get_bit(std::size_t index) const;
  void set_bit(std::size_t index);
  void mask_tail();
};

}  // namespace veil::session
