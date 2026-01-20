#include "transport/mux/ack_bitmap.h"

#include <cstdint>

namespace veil::mux {

namespace {

// Wraparound-aware comparison: returns true if seq1 is "less than" seq2
// considering potential sequence number wraparound.
// Uses signed comparison of the difference to handle wraparound correctly.
// This works because the difference between two uint64_t values, when cast
// to int64_t, correctly represents the signed distance even across wraparound.
bool seq_less_than(std::uint64_t seq1, std::uint64_t seq2) {
  return static_cast<std::int64_t>(seq1 - seq2) < 0;
}

}  // namespace

void AckBitmap::ack(std::uint64_t seq) {
  if (!initialized_) {
    head_ = seq;
    bitmap_ = 0;
    initialized_ = true;
    return;
  }
  // Use wraparound-aware comparison instead of direct comparison
  if (seq_less_than(head_, seq)) {  // seq > head_ (wraparound-aware)
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
  // Use wraparound-aware comparison instead of direct comparison
  if (seq_less_than(head_, seq)) {  // seq > head_ (wraparound-aware)
    return false;
  }
  const auto diff = head_ - seq;
  if (diff == 0) return true;
  if (diff > 32) return false;
  return ((bitmap_ >> (diff - 1)) & 1U) != 0U;
}

}  // namespace veil::mux
