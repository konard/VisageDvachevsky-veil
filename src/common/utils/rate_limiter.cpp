#include "common/utils/rate_limiter.h"

#include <algorithm>
#include <chrono>

namespace veil::utils {

TokenBucket::TokenBucket(double capacity, std::chrono::milliseconds interval,
                         std::function<Clock::time_point()> now_fn)
    : capacity_(capacity),
      tokens_(capacity),
      refill_per_ms_(capacity / static_cast<double>(interval.count())),
      now_fn_(std::move(now_fn)),
      last_refill_(now_fn_()) {}

void TokenBucket::refill() {
  const auto now = now_fn_();
  const auto elapsed_ms =
      std::chrono::duration_cast<std::chrono::milliseconds>(now - last_refill_).count();
  if (elapsed_ms <= 0) {
    return;
  }
  tokens_ = std::min(capacity_, tokens_ + refill_per_ms_ * static_cast<double>(elapsed_ms));
  last_refill_ = now;
}

bool TokenBucket::allow() {
  refill();
  if (tokens_ < 1.0) {
    return false;
  }
  tokens_ -= 1.0;
  return true;
}

}  // namespace veil::utils
