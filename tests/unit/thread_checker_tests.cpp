#include "common/utils/thread_checker.h"

#include <gtest/gtest.h>

#include <atomic>
#include <thread>
#include <vector>

namespace veil::utils::test {

class ThreadCheckerTest : public ::testing::Test {};

TEST_F(ThreadCheckerTest, CheckPassesOnOwnerThread) {
  ThreadChecker checker;

  // Should not assert - we're on the owner thread
  EXPECT_NO_FATAL_FAILURE(checker.check());
  EXPECT_TRUE(checker.is_owner_thread());
}

TEST_F(ThreadCheckerTest, IsOwnerThreadReturnsTrueOnOwnerThread) {
  ThreadChecker checker;
  EXPECT_TRUE(checker.is_owner_thread());
}

#ifndef NDEBUG
TEST_F(ThreadCheckerTest, IsOwnerThreadReturnsFalseOnDifferentThread) {
  ThreadChecker checker;
  std::atomic<bool> is_owner{true};

  std::thread other_thread([&checker, &is_owner]() {
    // On a different thread, is_owner_thread should return false
    is_owner = checker.is_owner_thread();
  });
  other_thread.join();

  EXPECT_FALSE(is_owner.load());
}
#endif

TEST_F(ThreadCheckerTest, DetachAllowsRebinding) {
  ThreadChecker checker;

  // Initially owns current thread
  EXPECT_TRUE(checker.is_owner_thread());

  // Detach - checker is now unbound
  checker.detach();

  // Rebind to current thread
  checker.rebind_to_current();
  EXPECT_TRUE(checker.is_owner_thread());
}

TEST_F(ThreadCheckerTest, RebindToCurrentChangesOwner) {
  ThreadChecker checker;
  std::atomic<bool> rebound_is_owner{false};

  std::thread other_thread([&checker, &rebound_is_owner]() {
    // Rebind to this thread
    checker.rebind_to_current();
    rebound_is_owner = checker.is_owner_thread();
  });
  other_thread.join();

  EXPECT_TRUE(rebound_is_owner.load());
  // Original thread is no longer the owner
#ifndef NDEBUG
  EXPECT_FALSE(checker.is_owner_thread());
#endif
}

TEST_F(ThreadCheckerTest, MoveConstructorTransfersOwnership) {
  ThreadChecker original;
  EXPECT_TRUE(original.is_owner_thread());

  ThreadChecker moved(std::move(original));
  EXPECT_TRUE(moved.is_owner_thread());

  // After move, original should be detached (any thread is accepted)
  // In debug mode, detached checker has empty thread::id
#ifndef NDEBUG
  // A detached checker's owner_thread_id is default (empty)
  // NOLINTNEXTLINE(bugprone-use-after-move)
  EXPECT_EQ(original.owner_thread_id(), std::thread::id{});
#endif
}

TEST_F(ThreadCheckerTest, MoveAssignmentTransfersOwnership) {
  ThreadChecker original;
  ThreadChecker target;

  EXPECT_TRUE(original.is_owner_thread());
  EXPECT_TRUE(target.is_owner_thread());

  target = std::move(original);
  EXPECT_TRUE(target.is_owner_thread());

#ifndef NDEBUG
  // NOLINTNEXTLINE(bugprone-use-after-move)
  EXPECT_EQ(original.owner_thread_id(), std::thread::id{});
#endif
}

#ifndef NDEBUG
TEST_F(ThreadCheckerTest, OwnerThreadIdReturnsCorrectId) {
  ThreadChecker checker;
  EXPECT_EQ(checker.owner_thread_id(), std::this_thread::get_id());
}
#endif

TEST_F(ThreadCheckerTest, ScopedThreadCheckRunsOnEntry) {
  ThreadChecker checker;

  // Should not assert - we're on the owner thread
  EXPECT_NO_FATAL_FAILURE({ ScopedThreadCheck scoped(checker); });
}

TEST_F(ThreadCheckerTest, MacrosCompile) {
  // Test that macros compile correctly
  VEIL_THREAD_CHECKER(checker);
  VEIL_DCHECK_THREAD(checker);

  // This should compile and not crash
  {
    VEIL_DCHECK_THREAD_SCOPE(checker);
    // Do some work here
    (void)checker.is_owner_thread();
  }
}

// Example class demonstrating ThreadChecker usage pattern
class ExampleSingleThreadedComponent {
 public:
  ExampleSingleThreadedComponent() = default;

  void do_work() {
    VEIL_DCHECK_THREAD(thread_checker_);
    work_count_++;
  }

  int work_count() const {
    VEIL_DCHECK_THREAD(thread_checker_);
    return work_count_;
  }

 private:
  VEIL_THREAD_CHECKER(thread_checker_);
  int work_count_{0};
};

TEST_F(ThreadCheckerTest, ExampleComponentWorksOnSameThread) {
  ExampleSingleThreadedComponent component;

  // All operations on the same thread should succeed
  EXPECT_NO_FATAL_FAILURE({
    component.do_work();
    component.do_work();
    EXPECT_EQ(component.work_count(), 2);
  });
}

#ifndef NDEBUG
// This test verifies the death behavior when check() fails on wrong thread.
// Only run in debug mode since release mode doesn't assert.
TEST_F(ThreadCheckerTest, CheckFailsOnWrongThread) {
  ThreadChecker checker;

  // This death test verifies that check() triggers an assertion
  // when called from a different thread.
  EXPECT_DEATH(
      {
        std::thread other([&checker]() { checker.check(); });
        other.join();
      },
      "");  // Message varies by platform, just check it dies
}
#endif

}  // namespace veil::utils::test
