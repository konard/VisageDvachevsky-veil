#include <gtest/gtest.h>

#include <vector>

#include "transport/mux/fragment_reassembly.h"

namespace veil::tests {

TEST(FragmentReassemblyTests, ReassemblesWhenComplete) {
  mux::FragmentReassembly r;
  EXPECT_TRUE(r.push(1, mux::Fragment{0, {1, 2}, false}));
  EXPECT_TRUE(r.push(1, mux::Fragment{2, {3}, true}));
  auto out = r.try_reassemble(1);
  ASSERT_TRUE(out.has_value());
  EXPECT_EQ(*out, (std::vector<std::uint8_t>{1, 2, 3}));
}

TEST(FragmentReassemblyTests, RejectsGaps) {
  mux::FragmentReassembly r;
  EXPECT_TRUE(r.push(1, mux::Fragment{0, {1, 2}, false}));
  EXPECT_TRUE(r.push(1, mux::Fragment{3, {4}, true}));
  auto out = r.try_reassemble(1);
  EXPECT_FALSE(out.has_value());
}

TEST(FragmentReassemblyTests, RespectsLimit) {
  mux::FragmentReassembly r(2);
  EXPECT_TRUE(r.push(1, mux::Fragment{0, {1}, false}));
  EXPECT_FALSE(r.push(1, mux::Fragment{1, {2, 3}, true}));
}

}  // namespace veil::tests
