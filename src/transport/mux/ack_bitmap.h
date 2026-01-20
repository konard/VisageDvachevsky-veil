#pragma once

#include <cstdint>

namespace veil::mux {

// Maintains a 32-bit selective ack bitmap anchored at acks' highest number.
//
// This implementation uses wraparound-aware sequence number comparisons to
// correctly handle potential uint64_t sequence number overflow. While overflow
// is extremely unlikely in practice (requires 2^64 packets, ~18,500 years at
// 1M packets/sec), the implementation uses signed comparison of differences
// to ensure correct behavior even across wraparound boundaries.
//
// Sequence number ordering uses the standard TCP-style comparison:
//   seq1 < seq2  iff  (int64_t)(seq1 - seq2) < 0
//
// This works correctly for sequence numbers within 2^63 of each other, which
// is more than sufficient for the 32-packet bitmap window used here.
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
