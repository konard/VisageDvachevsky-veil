#include <cstdint>
#include <iostream>
#include <limits>

// Test the wraparound logic
bool seq_less_than(std::uint64_t seq1, std::uint64_t seq2) {
  return static_cast<std::int64_t>(seq1 - seq2) < 0;
}

int main() {
  constexpr std::uint64_t kNearMax = std::numeric_limits<std::uint64_t>::max() - 2;
  constexpr std::uint64_t kMax = std::numeric_limits<std::uint64_t>::max();
  constexpr std::uint64_t kZero = 0;

  std::cout << "Testing wraparound logic:\n";
  std::cout << "kNearMax = " << kNearMax << "\n";
  std::cout << "kMax = " << kMax << "\n";
  std::cout << "kZero = " << kZero << "\n\n";

  // Test: head = 0, check if kMax is within window
  std::uint64_t head = kZero;
  std::uint64_t seq = kMax;
  std::uint64_t diff = head - seq;

  std::cout << "head = " << head << ", seq = " << seq << "\n";
  std::cout << "seq_less_than(head, seq) = " << seq_less_than(head, seq) << " (should be false, seq > head)\n";
  std::cout << "seq_less_than(seq, head) = " << seq_less_than(seq, head) << " (should be true, seq < head in wraparound)\n";
  std::cout << "diff = head - seq = " << diff << " (unsigned)\n";
  std::cout << "diff = " << static_cast<std::int64_t>(diff) << " (signed)\n";
  std::cout << "diff within 32? " << (diff <= 32) << "\n\n";

  // Test: head = 0, seq = kNearMax
  seq = kNearMax;
  diff = head - seq;
  std::cout << "head = " << head << ", seq = " << seq << "\n";
  std::cout << "seq_less_than(head, seq) = " << seq_less_than(head, seq) << " (should be false)\n";
  std::cout << "seq_less_than(seq, head) = " << seq_less_than(seq, head) << " (should be true)\n";
  std::cout << "diff = head - seq = " << diff << " (unsigned)\n";
  std::cout << "diff = " << static_cast<std::int64_t>(diff) << " (signed)\n";
  std::cout << "diff within 32? " << (diff <= 32) << "\n\n";

  return 0;
}
