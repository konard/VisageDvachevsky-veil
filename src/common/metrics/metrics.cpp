#include "common/metrics/metrics.h"

#include <algorithm>
#include <cmath>
#include <sstream>

namespace veil::metrics {

// Histogram implementation.

Histogram::Histogram() : Histogram({0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0}) {}

Histogram::Histogram(std::vector<double> bucket_bounds)
    : bucket_bounds_(std::move(bucket_bounds)), bucket_counts_(bucket_bounds_.size() + 1) {
  std::sort(bucket_bounds_.begin(), bucket_bounds_.end());
  for (auto& count : bucket_counts_) {
    count.store(0, std::memory_order_relaxed);
  }
}

void Histogram::observe(double value) {
  // Find bucket.
  auto it = std::lower_bound(bucket_bounds_.begin(), bucket_bounds_.end(), value);
  std::size_t bucket = static_cast<std::size_t>(std::distance(bucket_bounds_.begin(), it));

  bucket_counts_[bucket].fetch_add(1, std::memory_order_relaxed);
  count_.fetch_add(1, std::memory_order_relaxed);

  // Atomic add for double (using CAS loop).
  double current = sum_.load(std::memory_order_relaxed);
  while (!sum_.compare_exchange_weak(current, current + value, std::memory_order_relaxed)) {
  }
}

std::vector<std::pair<double, std::uint64_t>> Histogram::buckets() const {
  std::vector<std::pair<double, std::uint64_t>> result;
  result.reserve(bucket_bounds_.size() + 1);

  for (std::size_t i = 0; i < bucket_bounds_.size(); ++i) {
    result.emplace_back(bucket_bounds_[i], bucket_counts_[i].load(std::memory_order_relaxed));
  }
  result.emplace_back(std::numeric_limits<double>::infinity(),
                      bucket_counts_.back().load(std::memory_order_relaxed));

  return result;
}

double Histogram::sum() const {
  return sum_.load(std::memory_order_relaxed);
}

std::uint64_t Histogram::count() const {
  return count_.load(std::memory_order_relaxed);
}

double Histogram::percentile(double p) const {
  auto total = count();
  if (total == 0) {
    return 0.0;
  }

  auto target = static_cast<std::uint64_t>(std::ceil(p * static_cast<double>(total)));
  std::uint64_t cumulative = 0;

  for (std::size_t i = 0; i < bucket_counts_.size(); ++i) {
    cumulative += bucket_counts_[i].load(std::memory_order_relaxed);
    if (cumulative >= target) {
      if (i < bucket_bounds_.size()) {
        return bucket_bounds_[i];
      }
      return std::numeric_limits<double>::infinity();
    }
  }

  return std::numeric_limits<double>::infinity();
}

void Histogram::reset() {
  for (auto& count : bucket_counts_) {
    count.store(0, std::memory_order_relaxed);
  }
  count_.store(0, std::memory_order_relaxed);
  sum_.store(0.0, std::memory_order_relaxed);
}

// Summary implementation.

Summary::Summary(std::size_t window_size) : window_size_(window_size), values_(window_size, 0.0) {}

void Summary::observe(double value) {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    values_[write_pos_] = value;
    write_pos_ = (write_pos_ + 1) % window_size_;
  }

  count_.fetch_add(1, std::memory_order_relaxed);

  // Atomic add for double.
  double current = sum_.load(std::memory_order_relaxed);
  while (!sum_.compare_exchange_weak(current, current + value, std::memory_order_relaxed)) {
  }

  // Update min.
  double current_min = min_.load(std::memory_order_relaxed);
  while (value < current_min &&
         !min_.compare_exchange_weak(current_min, value, std::memory_order_relaxed)) {
  }

  // Update max.
  double current_max = max_.load(std::memory_order_relaxed);
  while (value > current_max &&
         !max_.compare_exchange_weak(current_max, value, std::memory_order_relaxed)) {
  }
}

double Summary::sum() const {
  return sum_.load(std::memory_order_relaxed);
}

double Summary::mean() const {
  auto c = count();
  if (c == 0) {
    return 0.0;
  }
  return sum() / static_cast<double>(c);
}

double Summary::percentile(double p) const {
  std::lock_guard<std::mutex> lock(mutex_);

  auto n = std::min(count_.load(std::memory_order_relaxed), window_size_);
  if (n == 0) {
    return 0.0;
  }

  std::vector<double> sorted(values_.begin(), values_.begin() + static_cast<std::ptrdiff_t>(n));
  std::sort(sorted.begin(), sorted.end());

  auto index = static_cast<std::size_t>(p * static_cast<double>(n - 1));
  return sorted[index];
}

double Summary::min() const {
  auto m = min_.load(std::memory_order_relaxed);
  if (m == std::numeric_limits<double>::max()) {
    return 0.0;
  }
  return m;
}

double Summary::max() const {
  auto m = max_.load(std::memory_order_relaxed);
  if (m == std::numeric_limits<double>::lowest()) {
    return 0.0;
  }
  return m;
}

void Summary::reset() {
  std::lock_guard<std::mutex> lock(mutex_);
  std::fill(values_.begin(), values_.end(), 0.0);
  write_pos_ = 0;
  count_.store(0, std::memory_order_relaxed);
  sum_.store(0.0, std::memory_order_relaxed);
  min_.store(std::numeric_limits<double>::max(), std::memory_order_relaxed);
  max_.store(std::numeric_limits<double>::lowest(), std::memory_order_relaxed);
}

// MetricRegistry implementation.

Counter& MetricRegistry::counter(const std::string& name) {
  std::lock_guard<std::mutex> lock(mutex_);

  auto it = counters_.find(name);
  if (it != counters_.end()) {
    return *it->second;
  }

  auto counter = std::make_unique<Counter>();
  auto& ref = *counter;
  counters_[name] = std::move(counter);
  return ref;
}

Gauge& MetricRegistry::gauge(const std::string& name) {
  std::lock_guard<std::mutex> lock(mutex_);

  auto it = gauges_.find(name);
  if (it != gauges_.end()) {
    return *it->second;
  }

  auto gauge = std::make_unique<Gauge>();
  auto& ref = *gauge;
  gauges_[name] = std::move(gauge);
  return ref;
}

Histogram& MetricRegistry::histogram(const std::string& name) {
  std::lock_guard<std::mutex> lock(mutex_);

  auto it = histograms_.find(name);
  if (it != histograms_.end()) {
    return *it->second;
  }

  auto histogram = std::make_unique<Histogram>();
  auto& ref = *histogram;
  histograms_[name] = std::move(histogram);
  return ref;
}

Histogram& MetricRegistry::histogram(const std::string& name, std::vector<double> buckets) {
  std::lock_guard<std::mutex> lock(mutex_);

  auto it = histograms_.find(name);
  if (it != histograms_.end()) {
    return *it->second;
  }

  auto histogram = std::make_unique<Histogram>(std::move(buckets));
  auto& ref = *histogram;
  histograms_[name] = std::move(histogram);
  return ref;
}

Summary& MetricRegistry::summary(const std::string& name, std::size_t window_size) {
  std::lock_guard<std::mutex> lock(mutex_);

  auto it = summaries_.find(name);
  if (it != summaries_.end()) {
    return *it->second;
  }

  auto summary = std::make_unique<Summary>(window_size);
  auto& ref = *summary;
  summaries_[name] = std::move(summary);
  return ref;
}

std::vector<std::string> MetricRegistry::metric_names() const {
  std::lock_guard<std::mutex> lock(mutex_);

  std::vector<std::string> names;
  names.reserve(counters_.size() + gauges_.size() + histograms_.size() + summaries_.size());

  for (const auto& [name, _] : counters_) {
    names.push_back(name);
  }
  for (const auto& [name, _] : gauges_) {
    names.push_back(name);
  }
  for (const auto& [name, _] : histograms_) {
    names.push_back(name);
  }
  for (const auto& [name, _] : summaries_) {
    names.push_back(name);
  }

  return names;
}

std::string MetricRegistry::export_json() const {
  std::lock_guard<std::mutex> lock(mutex_);

  std::ostringstream oss;
  oss << "{";

  bool first = true;

  // Export counters.
  for (const auto& [name, counter] : counters_) {
    if (!first) oss << ",";
    first = false;
    oss << "\"" << name << R"(":{"type":"counter","value":)" << counter->value() << "}";
  }

  // Export gauges.
  for (const auto& [name, gauge] : gauges_) {
    if (!first) oss << ",";
    first = false;
    oss << "\"" << name << R"(":{"type":"gauge","value":)" << gauge->value() << "}";
  }

  // Export histograms.
  for (const auto& [name, histogram] : histograms_) {
    if (!first) oss << ",";
    first = false;
    oss << "\"" << name << R"(":{"type":"histogram",)";
    oss << "\"count\":" << histogram->count() << ",";
    oss << "\"sum\":" << histogram->sum() << ",";
    oss << "\"p50\":" << histogram->percentile(0.5) << ",";
    oss << "\"p90\":" << histogram->percentile(0.9) << ",";
    oss << "\"p99\":" << histogram->percentile(0.99) << "}";
  }

  // Export summaries.
  for (const auto& [name, summary] : summaries_) {
    if (!first) oss << ",";
    first = false;
    oss << "\"" << name << R"(":{"type":"summary",)";
    oss << "\"count\":" << summary->count() << ",";
    oss << "\"sum\":" << summary->sum() << ",";
    oss << "\"mean\":" << summary->mean() << ",";
    oss << "\"min\":" << summary->min() << ",";
    oss << "\"max\":" << summary->max() << ",";
    oss << "\"p50\":" << summary->percentile(0.5) << ",";
    oss << "\"p90\":" << summary->percentile(0.9) << ",";
    oss << "\"p99\":" << summary->percentile(0.99) << "}";
  }

  oss << "}";
  return oss.str();
}

std::string MetricRegistry::export_prometheus(const std::string& prefix) const {
  std::lock_guard<std::mutex> lock(mutex_);

  std::ostringstream oss;

  // Export counters.
  for (const auto& [name, counter] : counters_) {
    oss << "# TYPE " << prefix << name << " counter\n";
    oss << prefix << name << " " << counter->value() << "\n";
  }

  // Export gauges.
  for (const auto& [name, gauge] : gauges_) {
    oss << "# TYPE " << prefix << name << " gauge\n";
    oss << prefix << name << " " << gauge->value() << "\n";
  }

  // Export histograms.
  for (const auto& [name, histogram] : histograms_) {
    oss << "# TYPE " << prefix << name << " histogram\n";
    auto buckets = histogram->buckets();
    std::uint64_t cumulative = 0;
    for (const auto& [bound, count] : buckets) {
      cumulative += count;
      if (bound == std::numeric_limits<double>::infinity()) {
        oss << prefix << name << "_bucket{le=\"+Inf\"} " << cumulative << "\n";
      } else {
        oss << prefix << name << "_bucket{le=\"" << bound << "\"} " << cumulative << "\n";
      }
    }
    oss << prefix << name << "_sum " << histogram->sum() << "\n";
    oss << prefix << name << "_count " << histogram->count() << "\n";
  }

  // Export summaries.
  for (const auto& [name, summary] : summaries_) {
    oss << "# TYPE " << prefix << name << " summary\n";
    oss << prefix << name << "{quantile=\"0.5\"} " << summary->percentile(0.5) << "\n";
    oss << prefix << name << "{quantile=\"0.9\"} " << summary->percentile(0.9) << "\n";
    oss << prefix << name << "{quantile=\"0.99\"} " << summary->percentile(0.99) << "\n";
    oss << prefix << name << "_sum " << summary->sum() << "\n";
    oss << prefix << name << "_count " << summary->count() << "\n";
  }

  return oss.str();
}

void MetricRegistry::reset_all() {
  std::lock_guard<std::mutex> lock(mutex_);

  for (auto& [_, counter] : counters_) {
    counter->reset();
  }
  for (auto& [_, gauge] : gauges_) {
    gauge->set(0.0);
  }
  for (auto& [_, histogram] : histograms_) {
    histogram->reset();
  }
  for (auto& [_, summary] : summaries_) {
    summary->reset();
  }
}

bool MetricRegistry::remove(const std::string& name) {
  std::lock_guard<std::mutex> lock(mutex_);

  if (counters_.erase(name) > 0) return true;
  if (gauges_.erase(name) > 0) return true;
  if (histograms_.erase(name) > 0) return true;
  if (summaries_.erase(name) > 0) return true;

  return false;
}

bool MetricRegistry::exists(const std::string& name) const {
  std::lock_guard<std::mutex> lock(mutex_);

  return counters_.count(name) > 0 || gauges_.count(name) > 0 || histograms_.count(name) > 0 ||
         summaries_.count(name) > 0;
}

// Global registry.

MetricRegistry& get_registry() {
  static MetricRegistry registry;
  return registry;
}

// ScopedTimer implementation.

ScopedTimer::ScopedTimer(Histogram& histogram) : histogram_(&histogram), start_(Clock::now()) {}

ScopedTimer::ScopedTimer(Summary& summary) : summary_(&summary), start_(Clock::now()) {}

ScopedTimer::~ScopedTimer() {
  if (!stopped_) {
    stop();
  }
}

std::chrono::nanoseconds ScopedTimer::stop() {
  if (stopped_) {
    return std::chrono::nanoseconds(0);
  }

  auto end = Clock::now();
  auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start_);
  auto seconds = std::chrono::duration<double>(duration).count();

  if (histogram_ != nullptr) {
    histogram_->observe(seconds);
  }
  if (summary_ != nullptr) {
    summary_->observe(seconds);
  }

  stopped_ = true;
  return duration;
}

// ThroughputTracker implementation.

ThroughputTracker::ThroughputTracker(std::chrono::seconds window,
                                     std::function<Clock::time_point()> now_fn)
    : window_(window), now_fn_(std::move(now_fn)), window_start_(now_fn_()) {}

void ThroughputTracker::record(std::uint64_t count) {
  total_.fetch_add(count, std::memory_order_relaxed);

  std::lock_guard<std::mutex> lock(mutex_);

  auto now = now_fn_();
  auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - window_start_);

  if (elapsed >= window_) {
    window_start_ = now;
    count_in_window_.store(count, std::memory_order_relaxed);
  } else {
    count_in_window_.fetch_add(count, std::memory_order_relaxed);
  }
}

double ThroughputTracker::throughput() const {
  std::lock_guard<std::mutex> lock(mutex_);

  auto now = now_fn_();
  auto elapsed = std::chrono::duration<double>(now - window_start_);

  if (elapsed.count() <= 0.0) {
    return 0.0;
  }

  auto count = count_in_window_.load(std::memory_order_relaxed);
  return static_cast<double>(count) / elapsed.count();
}

void ThroughputTracker::reset() {
  std::lock_guard<std::mutex> lock(mutex_);
  count_in_window_.store(0, std::memory_order_relaxed);
  total_.store(0, std::memory_order_relaxed);
  window_start_ = now_fn_();
}

}  // namespace veil::metrics
