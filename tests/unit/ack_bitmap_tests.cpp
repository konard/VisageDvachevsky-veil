#include <gtest/gtest.h>

#include "transport/mux/ack_bitmap.h"

namespace veil::tests {

TEST(AckBitmapTests, TracksHeadAndBitmap) {
  mux::AckBitmap bitmap;
  bitmap.ack(5);
  EXPECT_TRUE(bitmap.is_acked(5));
  EXPECT_FALSE(bitmap.is_acked(4));

  bitmap.ack(4);
  EXPECT_TRUE(bitmap.is_acked(4));

  bitmap.ack(9);
  EXPECT_TRUE(bitmap.is_acked(9));
  EXPECT_FALSE(bitmap.is_acked(5));  // outside window after shift
}

}  // namespace veil::tests
