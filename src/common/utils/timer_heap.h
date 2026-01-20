#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <limits>
#include <optional>
#include <queue>
#include <unordered_map>
#include <utility>
#include <vector>

namespace veil::utils {

// Timer identifier type.
using TimerId = std::uint64_t;

// Invalid timer ID constant.
constexpr TimerId kInvalidTimerId = std::numeric_limits<TimerId>::max();

// Timer callback type.
using TimerCallback = std::function<void(TimerId)>;

// Timer entry stored in the heap.
struct TimerEntry {
  TimerId id{0};
  std::chrono::steady_clock::time_point deadline;
  TimerCallback callback;

  // Min-heap comparison (earlier deadline = higher priority).
  bool operator>(const TimerEntry& other) const { return deadline > other.deadline; }
};

// Timer heap for scheduling and managing timed events.
// Uses a min-heap (priority queue) for efficient deadline tracking.
class TimerHeap {
 public:
  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;
  using Duration = Clock::duration;

  explicit TimerHeap(std::function<TimePoint()> now_fn = Clock::now);

  // Schedule a timer to fire at absolute deadline.
  // Returns timer ID for cancellation.
  TimerId schedule_at(TimePoint deadline, TimerCallback callback);

  // Schedule a timer to fire after duration from now.
  // Returns timer ID for cancellation.
  TimerId schedule_after(Duration duration, TimerCallback callback);

  // Cancel a timer by ID. Returns true if timer was found and cancelled.
  bool cancel(TimerId id);

  // Reschedule an existing timer with new deadline.
  // Returns true if timer was found and rescheduled.
  bool reschedule(TimerId id, TimePoint new_deadline);

  // Reschedule an existing timer with new duration from now.
  bool reschedule_after(TimerId id, Duration duration);

  // Process all timers that have expired.
  // Returns number of timers fired.
  std::size_t process_expired();

  // Get time until next timer fires (nullopt if no timers).
  std::optional<Duration> time_until_next() const;

  // Get number of active timers.
  std::size_t size() const { return active_timers_.size(); }

  // Check if there are any active timers.
  bool empty() const { return active_timers_.empty(); }

  // Clear all timers.
  void clear();

 private:
  // Entry in the active timers map, tracking callback and expected deadline.
  struct ActiveTimerInfo {
    TimerCallback callback;
    TimePoint expected_deadline;  // Used to detect stale heap entries.
  };

  TimerId next_id_{0};
  std::function<TimePoint()> now_fn_;

  // Min-heap of timer entries.
  std::priority_queue<TimerEntry, std::vector<TimerEntry>, std::greater<>> heap_;

  // Map of active timer IDs to their info (for cancellation and reschedule tracking).
  std::unordered_map<TimerId, ActiveTimerInfo> active_timers_;
};

}  // namespace veil::utils
