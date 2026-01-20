#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <vector>

#include "common/crypto/random.h"

namespace veil::tests {

TEST(RandomTests, RandomBytesProducesData) {
  const auto data = crypto::random_bytes(32);
  ASSERT_EQ(data.size(), 32U);
  const bool all_zero = std::all_of(data.begin(), data.end(), [](std::uint8_t b) { return b == 0; });
  ASSERT_FALSE(all_zero);
}

TEST(RandomTests, RandomUint64Varies) {
  const auto a = crypto::random_uint64();
  const auto b = crypto::random_uint64();
  ASSERT_NE(a, b);
}

TEST(RandomTests, SecureZeroClearsBuffer) {
  std::vector<std::uint8_t> buffer(16, 0xAA);
  crypto::secure_zero(buffer);
  for (auto value : buffer) {
    ASSERT_EQ(value, 0);
  }
}

}  // namespace veil::tests
