#include "transport/mux/ack_bitmap.h"

#include <cstdint>

namespace veil::mux {

void AckBitmap::ack(std::uint64_t seq) {
  if (!initialized_) {
    head_ = seq;
    bitmap_ = 0;
    initialized_ = true;
    return;
  }
  if (seq > head_) {
    const auto shift = seq - head_;
    if (shift >= 32) {
      bitmap_ = 0;
    } else {
      bitmap_ <<= shift;
    }
    head_ = seq;
    return;
  }
  const auto diff = head_ - seq;
  if (diff == 0) {
    return;
  }
  if (diff > 32) {
    return;
  }
  bitmap_ |= (1U << (diff - 1));
}

bool AckBitmap::is_acked(std::uint64_t seq) const {
  if (!initialized_) {
    return false;
  }
  if (seq == head_) {
    return true;
  }
  if (seq > head_) {
    return false;
  }
  const auto diff = head_ - seq;
  if (diff == 0) return true;
  if (diff > 32) return false;
  return ((bitmap_ >> (diff - 1)) & 1U) != 0U;
}

}  // namespace veil::mux
