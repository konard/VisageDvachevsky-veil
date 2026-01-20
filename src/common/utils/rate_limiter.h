#pragma once

#include <chrono>
#include <functional>

namespace veil::utils {

class TokenBucket {
 public:
  using Clock = std::chrono::steady_clock;

  TokenBucket(double capacity, std::chrono::milliseconds interval,
              std::function<Clock::time_point()> now_fn = Clock::now);

  bool allow();

 private:
  double capacity_;
  double tokens_;
  double refill_per_ms_;
  std::function<Clock::time_point()> now_fn_;
  Clock::time_point last_refill_;

  void refill();
};

}  // namespace veil::utils
