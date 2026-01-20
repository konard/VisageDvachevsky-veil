#include "common/utils/timer_heap.h"

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <utility>

namespace veil::utils {

TimerHeap::TimerHeap(std::function<TimePoint()> now_fn) : now_fn_(std::move(now_fn)) {}

TimerId TimerHeap::schedule_at(TimePoint deadline, TimerCallback callback) {
  const TimerId id = next_id_++;
  active_timers_[id] = ActiveTimerInfo{callback, deadline};
  heap_.push(TimerEntry{id, deadline, std::move(callback)});
  return id;
}

TimerId TimerHeap::schedule_after(Duration duration, TimerCallback callback) {
  return schedule_at(now_fn_() + duration, std::move(callback));
}

bool TimerHeap::cancel(TimerId id) {
  auto it = active_timers_.find(id);
  if (it == active_timers_.end()) {
    return false;
  }
  active_timers_.erase(it);
  // Note: Entry stays in heap but will be skipped when processed.
  return true;
}

bool TimerHeap::reschedule(TimerId id, TimePoint new_deadline) {
  auto it = active_timers_.find(id);
  if (it == active_timers_.end()) {
    return false;
  }

  // Update expected deadline and re-insert with new deadline.
  // Old entry stays in heap but will be skipped because deadline won't match.
  it->second.expected_deadline = new_deadline;
  heap_.push(TimerEntry{id, new_deadline, it->second.callback});
  return true;
}

bool TimerHeap::reschedule_after(TimerId id, Duration duration) {
  return reschedule(id, now_fn_() + duration);
}

std::size_t TimerHeap::process_expired() {
  const auto now = now_fn_();
  std::size_t fired = 0;

  while (!heap_.empty()) {
    const auto& top = heap_.top();

    // Check if timer has expired.
    if (top.deadline > now) {
      break;
    }

    // Extract entry.
    TimerEntry entry = heap_.top();
    heap_.pop();

    // Check if timer is still active (not cancelled).
    auto it = active_timers_.find(entry.id);
    if (it == active_timers_.end()) {
      // Timer was cancelled, skip.
      continue;
    }

    // Check if this is a stale entry from a rescheduled timer.
    // If the deadline doesn't match, this is an old entry that should be skipped.
    if (entry.deadline != it->second.expected_deadline) {
      continue;
    }

    // Remove from active set.
    active_timers_.erase(it);

    // Fire callback.
    if (entry.callback) {
      entry.callback(entry.id);
    }
    ++fired;
  }

  return fired;
}

std::optional<TimerHeap::Duration> TimerHeap::time_until_next() const {
  // Find next valid timer (skip cancelled and stale rescheduled ones).
  auto heap_copy = heap_;
  while (!heap_copy.empty()) {
    const auto& top = heap_copy.top();
    auto it = active_timers_.find(top.id);
    if (it != active_timers_.end() && top.deadline == it->second.expected_deadline) {
      const auto now = now_fn_();
      if (top.deadline <= now) {
        return Duration::zero();
      }
      return top.deadline - now;
    }
    heap_copy.pop();
  }
  return std::nullopt;
}

void TimerHeap::clear() {
  while (!heap_.empty()) {
    heap_.pop();
  }
  active_timers_.clear();
}

}  // namespace veil::utils
