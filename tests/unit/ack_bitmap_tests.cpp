#include <gtest/gtest.h>

#include <cstdint>
#include <limits>

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

// Test sequence number wraparound handling
TEST(AckBitmapTests, HandlesSequenceWraparound) {
  mux::AckBitmap bitmap;

  // Initialize near UINT64_MAX
  constexpr std::uint64_t kNearMax = std::numeric_limits<std::uint64_t>::max() - 10;
  bitmap.ack(kNearMax);
  EXPECT_TRUE(bitmap.is_acked(kNearMax));
  EXPECT_EQ(bitmap.head(), kNearMax);

  // Ack a sequence number that wraps around to small value
  constexpr std::uint64_t kWrappedSeq = 5;  // After wraparound
  bitmap.ack(kWrappedSeq);
  EXPECT_TRUE(bitmap.is_acked(kWrappedSeq));
  EXPECT_EQ(bitmap.head(), kWrappedSeq);

  // The old sequence should no longer be in the window
  EXPECT_FALSE(bitmap.is_acked(kNearMax));
}

TEST(AckBitmapTests, WraparoundWithinBitmapWindow) {
  mux::AckBitmap bitmap;

  // Initialize near UINT64_MAX
  constexpr std::uint64_t kNearMax = std::numeric_limits<std::uint64_t>::max() - 2;
  bitmap.ack(kNearMax);
  EXPECT_TRUE(bitmap.is_acked(kNearMax));

  // Ack UINT64_MAX (shift by 2, bitmap window moves)
  bitmap.ack(std::numeric_limits<std::uint64_t>::max());
  EXPECT_TRUE(bitmap.is_acked(std::numeric_limits<std::uint64_t>::max()));

  // Ack after wraparound (shift by 1)
  bitmap.ack(0);
  EXPECT_TRUE(bitmap.is_acked(0));

  // Now explicitly ack UINT64_MAX again (backward ack within window)
  // This tests that wraparound-aware comparison allows backward ack
  bitmap.ack(std::numeric_limits<std::uint64_t>::max());
  EXPECT_TRUE(bitmap.is_acked(std::numeric_limits<std::uint64_t>::max()));

  // Ack kNearMax explicitly (backward ack within window)
  bitmap.ack(kNearMax);
  EXPECT_TRUE(bitmap.is_acked(kNearMax));
}

TEST(AckBitmapTests, WraparoundBackwardAck) {
  mux::AckBitmap bitmap;

  // Start after wraparound
  bitmap.ack(10);
  EXPECT_TRUE(bitmap.is_acked(10));

  // Ack older sequences within window (after wraparound)
  bitmap.ack(9);
  EXPECT_TRUE(bitmap.is_acked(9));

  bitmap.ack(5);
  EXPECT_TRUE(bitmap.is_acked(5));

  // Try to ack a very old sequence from before wraparound
  // With head=10 and kBeforeWrap near UINT64_MAX, the difference is huge
  constexpr std::uint64_t kBeforeWrap = std::numeric_limits<std::uint64_t>::max() - 5;
  bitmap.ack(kBeforeWrap);

  // With wraparound-aware comparison, seq_less_than(10, kBeforeWrap) = false
  // because kBeforeWrap is actually "less than" 10 in wraparound semantics
  // But the diff = 10 - kBeforeWrap wraps to a large number > 32
  // Actually: 10 - (UINT64_MAX - 5) = 10 - UINT64_MAX + 5 = 16 (wraps around)
  // So it's within the 32-packet window!
  // But since we never explicitly acked it before, and we just tried to ack it,
  // let's check if it gets added
  EXPECT_TRUE(bitmap.is_acked(kBeforeWrap));
}

TEST(AckBitmapTests, LargeSequenceJump) {
  mux::AckBitmap bitmap;

  // Start at a normal sequence
  bitmap.ack(1000);
  EXPECT_TRUE(bitmap.is_acked(1000));

  // Large jump forward (> 32)
  bitmap.ack(1100);
  EXPECT_TRUE(bitmap.is_acked(1100));
  EXPECT_FALSE(bitmap.is_acked(1000));  // Outside window now

  // Ack old sequence (too old)
  bitmap.ack(1000);
  EXPECT_FALSE(bitmap.is_acked(1000));  // Still outside window
}

TEST(AckBitmapTests, ExactWraparoundBoundary) {
  mux::AckBitmap bitmap;

  // Test exactly at UINT64_MAX
  bitmap.ack(std::numeric_limits<std::uint64_t>::max());
  EXPECT_TRUE(bitmap.is_acked(std::numeric_limits<std::uint64_t>::max()));

  // Next sequence wraps to 0
  bitmap.ack(0);
  EXPECT_TRUE(bitmap.is_acked(0));
  EXPECT_EQ(bitmap.head(), 0);

  // Explicitly ack UINT64_MAX again (backward ack, diff = 1)
  // This tests that the wraparound calculation works correctly
  bitmap.ack(std::numeric_limits<std::uint64_t>::max());
  EXPECT_TRUE(bitmap.is_acked(std::numeric_limits<std::uint64_t>::max()));
}

}  // namespace veil::tests
