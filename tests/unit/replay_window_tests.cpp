#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <thread>

#include "common/session/replay_window.h"
#include "common/session/session_rotator.h"

namespace veil::tests {

TEST(ReplayWindowTests, RejectsDuplicatesAndOldSequences) {
  session::ReplayWindow window(64);
  EXPECT_TRUE(window.mark_and_check(10));
  EXPECT_FALSE(window.mark_and_check(10));
  EXPECT_TRUE(window.mark_and_check(11));
  EXPECT_FALSE(window.mark_and_check(11));
  EXPECT_FALSE(window.mark_and_check(10));
}

TEST(ReplayWindowTests, SlidesWindowForward) {
  session::ReplayWindow window(8);
  EXPECT_TRUE(window.mark_and_check(1));
  EXPECT_TRUE(window.mark_and_check(2));
  EXPECT_TRUE(window.mark_and_check(9));
  EXPECT_TRUE(window.mark_and_check(10));
  EXPECT_FALSE(window.mark_and_check(1));
}

TEST(SessionRotatorTests, RotatesAfterThresholds) {
  using namespace std::chrono_literals;
  session::SessionRotator rotator(1s, 2);
  const auto first = rotator.current();
  EXPECT_FALSE(rotator.should_rotate(1, std::chrono::steady_clock::now()));
  EXPECT_TRUE(rotator.should_rotate(2, std::chrono::steady_clock::now()));
  const auto second = rotator.rotate(std::chrono::steady_clock::now());
  EXPECT_NE(first, second);
  EXPECT_FALSE(rotator.should_rotate(0, std::chrono::steady_clock::now()));
  std::this_thread::sleep_for(1100ms);
  EXPECT_TRUE(rotator.should_rotate(0, std::chrono::steady_clock::now()));
}

}  // namespace veil::tests
