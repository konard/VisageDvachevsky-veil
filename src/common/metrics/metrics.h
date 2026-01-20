#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace veil::metrics {

// Metric types.
enum class MetricType : std::uint8_t {
  kCounter = 0,    // Monotonically increasing counter
  kGauge = 1,      // Arbitrary numeric value
  kHistogram = 2,  // Distribution of values
  kSummary = 3     // Quantile summary
};

// Counter - monotonically increasing value.
class Counter {
 public:
  Counter() = default;

  void increment(std::uint64_t value = 1) { value_.fetch_add(value, std::memory_order_relaxed); }

  std::uint64_t value() const { return value_.load(std::memory_order_relaxed); }

  void reset() { value_.store(0, std::memory_order_relaxed); }

 private:
  std::atomic<std::uint64_t> value_{0};
};

// Gauge - arbitrary numeric value that can go up or down.
class Gauge {
 public:
  Gauge() = default;

  void set(double value) {
    std::lock_guard<std::mutex> lock(mutex_);
    value_ = value;
  }

  void increment(double value = 1.0) {
    std::lock_guard<std::mutex> lock(mutex_);
    value_ += value;
  }

  void decrement(double value = 1.0) {
    std::lock_guard<std::mutex> lock(mutex_);
    value_ -= value;
  }

  double value() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return value_;
  }

 private:
  mutable std::mutex mutex_;
  double value_{0.0};
};

// Histogram for distribution tracking with fixed buckets.
class Histogram {
 public:
  // Create histogram with default buckets.
  Histogram();

  // Create histogram with custom bucket boundaries.
  explicit Histogram(std::vector<double> bucket_bounds);

  // Observe a value.
  void observe(double value);

  // Get bucket counts.
  std::vector<std::pair<double, std::uint64_t>> buckets() const;

  // Get sum of all observed values.
  double sum() const;

  // Get count of all observations.
  std::uint64_t count() const;

  // Get approximate percentile (linear interpolation).
  double percentile(double p) const;

  // Reset histogram.
  void reset();

 private:
  std::vector<double> bucket_bounds_;
  std::vector<std::atomic<std::uint64_t>> bucket_counts_;
  std::atomic<std::uint64_t> count_{0};
  std::atomic<double> sum_{0.0};
  mutable std::mutex mutex_;
};

// Summary for tracking quantiles with sliding window.
class Summary {
 public:
  // Create summary with window size.
  explicit Summary(std::size_t window_size = 1000);

  // Observe a value.
  void observe(double value);

  // Get count of observations.
  std::uint64_t count() const { return count_.load(std::memory_order_relaxed); }

  // Get sum of observations.
  double sum() const;

  // Get mean.
  double mean() const;

  // Get percentile (0.0 to 1.0).
  double percentile(double p) const;

  // Get min value.
  double min() const;

  // Get max value.
  double max() const;

  // Reset summary.
  void reset();

 private:
  std::size_t window_size_;
  std::vector<double> values_;
  std::size_t write_pos_{0};
  std::atomic<std::uint64_t> count_{0};
  std::atomic<double> sum_{0.0};
  std::atomic<double> min_{std::numeric_limits<double>::max()};
  std::atomic<double> max_{std::numeric_limits<double>::lowest()};
  mutable std::mutex mutex_;
};

// Aggregated statistics.
struct AggregatedStats {
  std::uint64_t count{0};
  double sum{0.0};
  double mean{0.0};
  double min{0.0};
  double max{0.0};
  double p50{0.0};
  double p90{0.0};
  double p99{0.0};
};

// Metric registry for managing all metrics.
class MetricRegistry {
 public:
  using Clock = std::chrono::steady_clock;

  MetricRegistry() = default;

  // Register or get a counter.
  Counter& counter(const std::string& name);

  // Register or get a gauge.
  Gauge& gauge(const std::string& name);

  // Register or get a histogram.
  Histogram& histogram(const std::string& name);

  // Register or get a histogram with custom buckets.
  Histogram& histogram(const std::string& name, std::vector<double> buckets);

  // Register or get a summary.
  Summary& summary(const std::string& name, std::size_t window_size = 1000);

  // Get all metric names.
  std::vector<std::string> metric_names() const;

  // Export all metrics as JSON.
  std::string export_json() const;

  // Export all metrics for Prometheus format.
  std::string export_prometheus(const std::string& prefix = "veil_") const;

  // Reset all metrics.
  void reset_all();

  // Remove a metric.
  bool remove(const std::string& name);

  // Check if metric exists.
  bool exists(const std::string& name) const;

 private:
  mutable std::mutex mutex_;
  std::unordered_map<std::string, std::unique_ptr<Counter>> counters_;
  std::unordered_map<std::string, std::unique_ptr<Gauge>> gauges_;
  std::unordered_map<std::string, std::unique_ptr<Histogram>> histograms_;
  std::unordered_map<std::string, std::unique_ptr<Summary>> summaries_;
};

// Global metric registry.
MetricRegistry& get_registry();

// Scoped timer for measuring durations.
class ScopedTimer {
 public:
  using Clock = std::chrono::steady_clock;

  // Timer that observes to a histogram.
  explicit ScopedTimer(Histogram& histogram);

  // Timer that observes to a summary.
  explicit ScopedTimer(Summary& summary);

  ~ScopedTimer();

  // Stop timer early and get duration.
  std::chrono::nanoseconds stop();

 private:
  Histogram* histogram_{nullptr};
  Summary* summary_{nullptr};
  Clock::time_point start_;
  bool stopped_{false};
};

// Throughput tracker for rate calculation.
class ThroughputTracker {
 public:
  using Clock = std::chrono::steady_clock;

  explicit ThroughputTracker(std::chrono::seconds window = std::chrono::seconds(1),
                             std::function<Clock::time_point()> now_fn = Clock::now);

  // Record an event.
  void record(std::uint64_t count = 1);

  // Get current throughput (events per second).
  double throughput() const;

  // Get total count.
  std::uint64_t total() const { return total_.load(std::memory_order_relaxed); }

  // Reset tracker.
  void reset();

 private:
  std::chrono::seconds window_;
  std::function<Clock::time_point()> now_fn_;
  std::atomic<std::uint64_t> count_in_window_{0};
  std::atomic<std::uint64_t> total_{0};
  Clock::time_point window_start_;
  mutable std::mutex mutex_;
};

// Convenient metric macros.
#define METRIC_COUNTER(name) ::veil::metrics::get_registry().counter(name)
#define METRIC_GAUGE(name) ::veil::metrics::get_registry().gauge(name)
#define METRIC_HISTOGRAM(name) ::veil::metrics::get_registry().histogram(name)
#define METRIC_SUMMARY(name) ::veil::metrics::get_registry().summary(name)

#define METRIC_TIME_HISTOGRAM(name, code)                        \
  do {                                                            \
    ::veil::metrics::ScopedTimer __timer(METRIC_HISTOGRAM(name)); \
    code;                                                         \
  } while (0)

#define METRIC_TIME_SUMMARY(name, code)                        \
  do {                                                          \
    ::veil::metrics::ScopedTimer __timer(METRIC_SUMMARY(name)); \
    code;                                                       \
  } while (0)

}  // namespace veil::metrics
