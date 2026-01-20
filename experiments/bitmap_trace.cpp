#include <cstdint>
#include <iostream>
#include <bitset>

// Simple version to trace
class SimpleBitmap {
public:
  void ack(std::uint64_t seq) {
    std::cout << "\nack(" << seq << "):\n";
    if (!initialized_) {
      head_ = seq;
      bitmap_ = 0;
      initialized_ = true;
      std::cout << "  Initialized: head=" << head_ << ", bitmap=0\n";
      return;
    }

    if (seq > head_) {
      auto shift = seq - head_;
      std::cout << "  Forward shift: old_head=" << head_ << ", shift=" << shift << "\n";
      std::cout << "  Before: bitmap=" << std::bitset<32>(bitmap_) << "\n";
      if (shift >= 32) {
        bitmap_ = 0;
      } else {
        bitmap_ <<= shift;
      }
      std::cout << "  After shift: bitmap=" << std::bitset<32>(bitmap_) << "\n";
      head_ = seq;
      std::cout << "  New head=" << head_ << "\n";
      return;
    }

    auto diff = head_ - seq;
    std::cout << "  Backward ack: head=" << head_ << ", diff=" << diff << "\n";
    if (diff == 0) {
      std::cout << "  Already head\n";
      return;
    }
    if (diff > 32) {
      std::cout << "  Too old (diff > 32)\n";
      return;
    }
    std::cout << "  Before: bitmap=" << std::bitset<32>(bitmap_) << "\n";
    bitmap_ |= (1U << (diff - 1));
    std::cout << "  After: bitmap=" << std::bitset<32>(bitmap_) << " (set bit " << (diff-1) << ")\n";
  }

  bool is_acked(std::uint64_t seq) const {
    if (!initialized_) return false;
    if (seq == head_) return true;
    if (seq > head_) return false;
    auto diff = head_ - seq;
    if (diff == 0) return true;
    if (diff > 32) return false;
    bool result = ((bitmap_ >> (diff - 1)) & 1U) != 0U;
    std::cout << "is_acked(" << seq << "): diff=" << diff << ", bit=" << (diff-1)
              << ", result=" << result << "\n";
    return result;
  }

private:
  std::uint64_t head_{0};
  std::uint32_t bitmap_{0};
  bool initialized_{false};
};

int main() {
  SimpleBitmap bitmap;

  std::cout << "Test 1: Normal sequence\n";
  std::cout << "========================\n";
  bitmap.ack(5);
  bitmap.ack(9);
  std::cout << "\nCheck if 5 is acked:\n";
  std::cout << "Result: " << bitmap.is_acked(5) << " (expected: 0, outside window)\n";

  std::cout << "\n\nTest 2: With backward ack\n";
  std::cout << "========================\n";
  SimpleBitmap bitmap2;
  bitmap2.ack(10);
  bitmap2.ack(15);
  std::cout << "\nNow ack 12 (backward):\n";
  bitmap2.ack(12);
  std::cout << "\nCheck if 12 is acked:\n";
  std::cout << "Result: " << bitmap2.is_acked(12) << " (expected: 1)\n";
  std::cout << "\nCheck if 10 is acked:\n";
  std::cout << "Result: " << bitmap2.is_acked(10) << " (expected: 0, outside window)\n";

  return 0;
}
