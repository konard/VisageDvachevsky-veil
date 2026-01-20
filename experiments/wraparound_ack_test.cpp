#include <cstdint>
#include <iostream>
#include <limits>
#include <bitset>

namespace {

bool seq_less_than(std::uint64_t seq1, std::uint64_t seq2) {
  return static_cast<std::int64_t>(seq1 - seq2) < 0;
}

}

class TestBitmap {
public:
  void ack(std::uint64_t seq) {
    std::cout << "\nack(" << seq << "):\n";
    if (!initialized_) {
      head_ = seq;
      bitmap_ = 0;
      initialized_ = true;
      std::cout << "  Init: head=" << head_ << "\n";
      return;
    }

    std::cout << "  Current state: head=" << head_ << ", bitmap=" << std::bitset<32>(bitmap_) << "\n";

    if (seq_less_than(head_, seq)) {
      auto shift = seq - head_;
      std::cout << "  Forward: seq_less_than(head=" << head_ << ", seq=" << seq << ") = true\n";
      std::cout << "  shift=" << shift << "\n";
      if (shift >= 32) {
        bitmap_ = 0;
      } else {
        bitmap_ <<= shift;
      }
      head_ = seq;
      std::cout << "  New state: head=" << head_ << ", bitmap=" << std::bitset<32>(bitmap_) << "\n";
      return;
    }

    std::cout << "  Backward: seq_less_than(head=" << head_ << ", seq=" << seq << ") = false\n";
    auto diff = head_ - seq;
    std::cout << "  diff = head - seq = " << head_ << " - " << seq << " = " << diff << "\n";

    if (diff == 0) {
      std::cout << "  diff == 0, already acked\n";
      return;
    }
    if (diff > 32) {
      std::cout << "  diff > 32, too old\n";
      return;
    }

    std::cout << "  Setting bit " << (diff - 1) << "\n";
    bitmap_ |= (1U << (diff - 1));
    std::cout << "  New bitmap=" << std::bitset<32>(bitmap_) << "\n";
  }

  bool is_acked(std::uint64_t seq) const {
    if (!initialized_) return false;
    if (seq == head_) return true;

    if (seq_less_than(head_, seq)) {
      std::cout << "is_acked(" << seq << "): seq > head (wraparound-aware), false\n";
      return false;
    }

    auto diff = head_ - seq;
    if (diff == 0) return true;
    if (diff > 32) {
      std::cout << "is_acked(" << seq << "): diff=" << diff << " > 32, false\n";
      return false;
    }

    bool result = ((bitmap_ >> (diff - 1)) & 1U) != 0U;
    std::cout << "is_acked(" << seq << "): diff=" << diff << ", bit=" << (diff-1) << ", result=" << result << "\n";
    return result;
  }

private:
  std::uint64_t head_{0};
  std::uint32_t bitmap_{0};
  bool initialized_{false};
};

int main() {
  TestBitmap bitmap;

  std::cout << "Test: Wraparound boundary\n";
  std::cout << "=========================\n";

  constexpr auto kMax = std::numeric_limits<std::uint64_t>::max();

  bitmap.ack(kMax);
  bitmap.ack(0);

  std::cout << "\nNow trying to backward ack kMax:\n";
  bitmap.ack(kMax);

  std::cout << "\nChecking if kMax is acked:\n";
  bool result = bitmap.is_acked(kMax);
  std::cout << "Result: " << result << " (expected true)\n";

  return 0;
}
