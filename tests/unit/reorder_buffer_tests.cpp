#include <gtest/gtest.h>

#include <vector>

#include "transport/mux/reorder_buffer.h"

namespace veil::tests {

TEST(ReorderBufferTests, AcceptsInOrder) {
  mux::ReorderBuffer buf(1);
  EXPECT_TRUE(buf.push(1, {1}));
  auto val = buf.pop_next();
  ASSERT_TRUE(val.has_value());
  EXPECT_EQ(val->at(0), 1);
  EXPECT_FALSE(buf.pop_next().has_value());
}

TEST(ReorderBufferTests, HoldsUntilInOrder) {
  mux::ReorderBuffer buf(1);
  EXPECT_TRUE(buf.push(2, {2}));
  EXPECT_FALSE(buf.pop_next().has_value());
  EXPECT_TRUE(buf.push(1, {1}));
  auto v1 = buf.pop_next();
  ASSERT_TRUE(v1.has_value());
  EXPECT_EQ(v1->at(0), 1);
  auto v2 = buf.pop_next();
  ASSERT_TRUE(v2.has_value());
  EXPECT_EQ(v2->at(0), 2);
}

TEST(ReorderBufferTests, RespectsBufferLimit) {
  mux::ReorderBuffer buf(1, 1);
  EXPECT_TRUE(buf.push(1, {1}));
  EXPECT_FALSE(buf.push(2, {1, 2}));
}

}  // namespace veil::tests
