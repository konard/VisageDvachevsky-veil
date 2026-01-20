#pragma once

#include <cstdint>

namespace veil::mux {

// Maintains a 32-bit selective ack bitmap anchored at acks' highest number.
class AckBitmap {
 public:
  AckBitmap() = default;

  void ack(std::uint64_t seq);
  bool is_acked(std::uint64_t seq) const;
  std::uint64_t head() const { return head_; }
  std::uint32_t bitmap() const { return bitmap_; }

 private:
  std::uint64_t head_{0};
  std::uint32_t bitmap_{0};
  bool initialized_{false};
};

}  // namespace veil::mux
