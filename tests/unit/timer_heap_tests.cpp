#include <gtest/gtest.h>

#include <chrono>
#include <vector>

#include "common/utils/timer_heap.h"

namespace veil::utils::tests {

using namespace std::chrono_literals;

class TimerHeapTest : public ::testing::Test {
 protected:
  void SetUp() override {
    test_now_ = std::chrono::steady_clock::now();
    heap_ = std::make_unique<TimerHeap>([this]() { return test_now_; });
  }

  void advance_time(std::chrono::steady_clock::duration duration) { test_now_ += duration; }

  std::chrono::steady_clock::time_point test_now_;
  std::unique_ptr<TimerHeap> heap_;
};

TEST_F(TimerHeapTest, EmptyHeap) {
  EXPECT_TRUE(heap_->empty());
  EXPECT_EQ(heap_->size(), 0U);
  EXPECT_FALSE(heap_->time_until_next().has_value());
}

TEST_F(TimerHeapTest, ScheduleAndFire) {
  bool fired = false;
  heap_->schedule_after(100ms, [&fired](TimerId) { fired = true; });

  EXPECT_FALSE(heap_->empty());
  EXPECT_EQ(heap_->size(), 1U);

  // Timer shouldn't fire yet.
  heap_->process_expired();
  EXPECT_FALSE(fired);

  // Advance time and fire.
  advance_time(100ms);
  std::size_t count = heap_->process_expired();
  EXPECT_EQ(count, 1U);
  EXPECT_TRUE(fired);
  EXPECT_TRUE(heap_->empty());
}

TEST_F(TimerHeapTest, MultipleTimersFireInOrder) {
  std::vector<int> fired_order;

  heap_->schedule_after(300ms, [&fired_order](TimerId) { fired_order.push_back(3); });
  heap_->schedule_after(100ms, [&fired_order](TimerId) { fired_order.push_back(1); });
  heap_->schedule_after(200ms, [&fired_order](TimerId) { fired_order.push_back(2); });

  EXPECT_EQ(heap_->size(), 3U);

  // Advance to 150ms - only first timer should fire.
  advance_time(150ms);
  heap_->process_expired();
  EXPECT_EQ(fired_order.size(), 1U);
  EXPECT_EQ(fired_order[0], 1);

  // Advance to 250ms - second timer should fire.
  advance_time(100ms);
  heap_->process_expired();
  EXPECT_EQ(fired_order.size(), 2U);
  EXPECT_EQ(fired_order[1], 2);

  // Advance to 350ms - third timer should fire.
  advance_time(100ms);
  heap_->process_expired();
  EXPECT_EQ(fired_order.size(), 3U);
  EXPECT_EQ(fired_order[2], 3);

  EXPECT_TRUE(heap_->empty());
}

TEST_F(TimerHeapTest, CancelTimer) {
  bool fired = false;
  TimerId id = heap_->schedule_after(100ms, [&fired](TimerId) { fired = true; });

  EXPECT_TRUE(heap_->cancel(id));
  EXPECT_EQ(heap_->size(), 0U);

  advance_time(200ms);
  heap_->process_expired();
  EXPECT_FALSE(fired);
}

TEST_F(TimerHeapTest, CancelNonexistentTimer) { EXPECT_FALSE(heap_->cancel(999)); }

TEST_F(TimerHeapTest, RescheduleTimer) {
  bool fired = false;
  TimerId id = heap_->schedule_after(100ms, [&fired](TimerId) { fired = true; });

  // Reschedule to 300ms.
  EXPECT_TRUE(heap_->reschedule_after(id, 300ms));

  // Advance to 150ms - shouldn't fire.
  advance_time(150ms);
  heap_->process_expired();
  EXPECT_FALSE(fired);

  // Advance to 350ms - should fire now.
  advance_time(200ms);
  heap_->process_expired();
  EXPECT_TRUE(fired);
}

TEST_F(TimerHeapTest, TimeUntilNext) {
  heap_->schedule_after(100ms, [](TimerId) {});
  heap_->schedule_after(300ms, [](TimerId) {});

  auto time = heap_->time_until_next();
  ASSERT_TRUE(time.has_value());
  EXPECT_GE(time->count(), 99000000);  // ~100ms
  EXPECT_LE(time->count(), 101000000);

  // Advance 50ms.
  advance_time(50ms);
  time = heap_->time_until_next();
  ASSERT_TRUE(time.has_value());
  EXPECT_GE(time->count(), 49000000);  // ~50ms
  EXPECT_LE(time->count(), 51000000);
}

TEST_F(TimerHeapTest, ClearAllTimers) {
  heap_->schedule_after(100ms, [](TimerId) {});
  heap_->schedule_after(200ms, [](TimerId) {});
  heap_->schedule_after(300ms, [](TimerId) {});

  EXPECT_EQ(heap_->size(), 3U);

  heap_->clear();

  EXPECT_TRUE(heap_->empty());
  EXPECT_EQ(heap_->size(), 0U);
}

TEST_F(TimerHeapTest, ScheduleAtAbsoluteTime) {
  bool fired = false;
  auto deadline = test_now_ + 100ms;
  heap_->schedule_at(deadline, [&fired](TimerId) { fired = true; });

  heap_->process_expired();
  EXPECT_FALSE(fired);

  advance_time(100ms);
  heap_->process_expired();
  EXPECT_TRUE(fired);
}

TEST_F(TimerHeapTest, ManyTimers) {
  constexpr int kNumTimers = 1000;
  int fired_count = 0;

  for (int i = 0; i < kNumTimers; ++i) {
    heap_->schedule_after(std::chrono::milliseconds(i), [&fired_count](TimerId) { ++fired_count; });
  }

  EXPECT_EQ(heap_->size(), kNumTimers);

  // Advance past all timers.
  advance_time(std::chrono::milliseconds(kNumTimers + 100));
  heap_->process_expired();

  EXPECT_EQ(fired_count, kNumTimers);
  EXPECT_TRUE(heap_->empty());
}

TEST_F(TimerHeapTest, CancelDuringCallback) {
  TimerId id1 = 0;
  TimerId id2 = 0;
  int fired_count = 0;

  // First timer cancels the second timer.
  id1 = heap_->schedule_after(100ms, [this, &id2, &fired_count](TimerId) {
    ++fired_count;
    heap_->cancel(id2);
  });
  id2 = heap_->schedule_after(100ms, [&fired_count](TimerId) { ++fired_count; });

  advance_time(100ms);
  heap_->process_expired();

  // Only one timer should have fired (order is deterministic by ID).
  EXPECT_EQ(fired_count, 1);
  (void)id1;  // Suppress unused variable warning.
}

}  // namespace veil::utils::tests
