#include <gtest/gtest.h>

#include <chrono>

#include "common/metrics/metrics.h"

namespace veil::metrics::test {

class MetricsTest : public ::testing::Test {
 protected:
  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;

  void SetUp() override { current_time_ = Clock::now(); }

  TimePoint now() { return current_time_; }

  void advance_time(std::chrono::milliseconds ms) { current_time_ += ms; }

  TimePoint current_time_;
};

// Counter tests.

TEST_F(MetricsTest, Counter_InitialValue) {
  Counter counter;
  EXPECT_EQ(counter.value(), 0u);
}

TEST_F(MetricsTest, Counter_Increment) {
  Counter counter;
  counter.increment();
  EXPECT_EQ(counter.value(), 1u);

  counter.increment(5);
  EXPECT_EQ(counter.value(), 6u);
}

TEST_F(MetricsTest, Counter_Reset) {
  Counter counter;
  counter.increment(100);
  counter.reset();
  EXPECT_EQ(counter.value(), 0u);
}

// Gauge tests.

TEST_F(MetricsTest, Gauge_SetAndGet) {
  Gauge gauge;
  gauge.set(42.5);
  EXPECT_DOUBLE_EQ(gauge.value(), 42.5);
}

TEST_F(MetricsTest, Gauge_IncrementDecrement) {
  Gauge gauge;
  gauge.set(10.0);
  gauge.increment(5.0);
  EXPECT_DOUBLE_EQ(gauge.value(), 15.0);

  gauge.decrement(3.0);
  EXPECT_DOUBLE_EQ(gauge.value(), 12.0);
}

// Histogram tests.

TEST_F(MetricsTest, Histogram_Observe) {
  Histogram histogram({0.1, 0.5, 1.0, 5.0, 10.0});

  histogram.observe(0.05);
  histogram.observe(0.3);
  histogram.observe(2.0);
  histogram.observe(7.5);

  EXPECT_EQ(histogram.count(), 4u);
  EXPECT_DOUBLE_EQ(histogram.sum(), 0.05 + 0.3 + 2.0 + 7.5);
}

TEST_F(MetricsTest, Histogram_Buckets) {
  Histogram histogram({1.0, 5.0, 10.0});

  histogram.observe(0.5);   // bucket 0 (< 1.0)
  histogram.observe(3.0);   // bucket 1 (< 5.0)
  histogram.observe(7.0);   // bucket 2 (< 10.0)
  histogram.observe(15.0);  // bucket 3 (+Inf)

  auto buckets = histogram.buckets();
  EXPECT_EQ(buckets.size(), 4u);  // 3 bounds + 1 for +Inf

  EXPECT_EQ(buckets[0].second, 1u);  // < 1.0
  EXPECT_EQ(buckets[1].second, 1u);  // < 5.0
  EXPECT_EQ(buckets[2].second, 1u);  // < 10.0
  EXPECT_EQ(buckets[3].second, 1u);  // +Inf
}

TEST_F(MetricsTest, Histogram_Percentile) {
  Histogram histogram({1.0, 2.0, 3.0, 4.0, 5.0});

  // Add values in different buckets.
  for (int i = 0; i < 10; i++) histogram.observe(0.5);
  for (int i = 0; i < 20; i++) histogram.observe(1.5);
  for (int i = 0; i < 30; i++) histogram.observe(2.5);
  for (int i = 0; i < 40; i++) histogram.observe(3.5);

  // p50 should be in the 2.0-3.0 range.
  EXPECT_LE(histogram.percentile(0.5), 3.0);

  // p90 should be in the higher buckets.
  EXPECT_GE(histogram.percentile(0.9), 3.0);
}

TEST_F(MetricsTest, Histogram_Reset) {
  Histogram histogram({1.0, 5.0});

  histogram.observe(2.0);
  histogram.observe(3.0);
  histogram.reset();

  EXPECT_EQ(histogram.count(), 0u);
  EXPECT_DOUBLE_EQ(histogram.sum(), 0.0);
}

// Summary tests.

TEST_F(MetricsTest, Summary_Observe) {
  Summary summary(100);

  for (int i = 1; i <= 10; i++) {
    summary.observe(static_cast<double>(i));
  }

  EXPECT_EQ(summary.count(), 10u);
  EXPECT_DOUBLE_EQ(summary.sum(), 55.0);
  EXPECT_DOUBLE_EQ(summary.mean(), 5.5);
  EXPECT_DOUBLE_EQ(summary.min(), 1.0);
  EXPECT_DOUBLE_EQ(summary.max(), 10.0);
}

TEST_F(MetricsTest, Summary_Percentile) {
  Summary summary(100);

  for (int i = 1; i <= 100; i++) {
    summary.observe(static_cast<double>(i));
  }

  EXPECT_NEAR(summary.percentile(0.5), 50.0, 5.0);
  EXPECT_NEAR(summary.percentile(0.9), 90.0, 5.0);
  EXPECT_NEAR(summary.percentile(0.99), 99.0, 5.0);
}

TEST_F(MetricsTest, Summary_SlidingWindow) {
  Summary summary(5);  // Small window.

  // Fill window.
  for (int i = 1; i <= 5; i++) {
    summary.observe(static_cast<double>(i));
  }

  // Add more values - window should slide.
  summary.observe(100.0);
  summary.observe(100.0);

  // Max should now be 100 (from recent values).
  EXPECT_DOUBLE_EQ(summary.max(), 100.0);
}

TEST_F(MetricsTest, Summary_Reset) {
  Summary summary(100);

  summary.observe(10.0);
  summary.observe(20.0);
  summary.reset();

  EXPECT_EQ(summary.count(), 0u);
  EXPECT_DOUBLE_EQ(summary.sum(), 0.0);
  EXPECT_DOUBLE_EQ(summary.min(), 0.0);
  EXPECT_DOUBLE_EQ(summary.max(), 0.0);
}

// MetricRegistry tests.

TEST_F(MetricsTest, Registry_Counter) {
  MetricRegistry registry;

  auto& counter1 = registry.counter("requests_total");
  auto& counter2 = registry.counter("requests_total");

  counter1.increment();
  EXPECT_EQ(counter2.value(), 1u);  // Same counter.
}

TEST_F(MetricsTest, Registry_Gauge) {
  MetricRegistry registry;

  auto& gauge = registry.gauge("active_connections");
  gauge.set(42);
  EXPECT_DOUBLE_EQ(registry.gauge("active_connections").value(), 42.0);
}

TEST_F(MetricsTest, Registry_Histogram) {
  MetricRegistry registry;

  auto& histogram = registry.histogram("request_latency");
  histogram.observe(0.1);
  histogram.observe(0.2);

  EXPECT_EQ(registry.histogram("request_latency").count(), 2u);
}

TEST_F(MetricsTest, Registry_HistogramWithBuckets) {
  MetricRegistry registry;

  auto& histogram = registry.histogram("custom_histogram", {0.1, 0.5, 1.0});
  auto buckets = histogram.buckets();
  EXPECT_EQ(buckets.size(), 4u);  // 3 bounds + Inf.
}

TEST_F(MetricsTest, Registry_Summary) {
  MetricRegistry registry;

  auto& summary = registry.summary("response_time", 50);
  summary.observe(1.0);
  summary.observe(2.0);

  EXPECT_EQ(registry.summary("response_time", 50).count(), 2u);
}

TEST_F(MetricsTest, Registry_MetricNames) {
  MetricRegistry registry;

  registry.counter("counter1");
  registry.gauge("gauge1");
  registry.histogram("histogram1");
  registry.summary("summary1");

  auto names = registry.metric_names();
  EXPECT_EQ(names.size(), 4u);
}

TEST_F(MetricsTest, Registry_Exists) {
  MetricRegistry registry;

  registry.counter("my_counter");

  EXPECT_TRUE(registry.exists("my_counter"));
  EXPECT_FALSE(registry.exists("nonexistent"));
}

TEST_F(MetricsTest, Registry_Remove) {
  MetricRegistry registry;

  registry.counter("my_counter");
  EXPECT_TRUE(registry.exists("my_counter"));

  EXPECT_TRUE(registry.remove("my_counter"));
  EXPECT_FALSE(registry.exists("my_counter"));

  EXPECT_FALSE(registry.remove("nonexistent"));
}

TEST_F(MetricsTest, Registry_ResetAll) {
  MetricRegistry registry;

  registry.counter("counter").increment(10);
  registry.gauge("gauge").set(42);
  registry.histogram("histogram").observe(1.0);
  registry.summary("summary").observe(2.0);

  registry.reset_all();

  EXPECT_EQ(registry.counter("counter").value(), 0u);
  EXPECT_DOUBLE_EQ(registry.gauge("gauge").value(), 0.0);
  EXPECT_EQ(registry.histogram("histogram").count(), 0u);
  EXPECT_EQ(registry.summary("summary").count(), 0u);
}

TEST_F(MetricsTest, Registry_ExportJson) {
  MetricRegistry registry;

  registry.counter("requests").increment(100);
  registry.gauge("connections").set(42);

  auto json = registry.export_json();

  EXPECT_NE(json.find("\"requests\""), std::string::npos);
  EXPECT_NE(json.find("\"counter\""), std::string::npos);
  EXPECT_NE(json.find("\"connections\""), std::string::npos);
  EXPECT_NE(json.find("\"gauge\""), std::string::npos);
}

TEST_F(MetricsTest, Registry_ExportPrometheus) {
  MetricRegistry registry;

  registry.counter("requests").increment(100);
  registry.gauge("connections").set(42);

  auto prom = registry.export_prometheus("test_");

  EXPECT_NE(prom.find("# TYPE test_requests counter"), std::string::npos);
  EXPECT_NE(prom.find("test_requests 100"), std::string::npos);
  EXPECT_NE(prom.find("# TYPE test_connections gauge"), std::string::npos);
  EXPECT_NE(prom.find("test_connections 42"), std::string::npos);
}

// ScopedTimer tests.

TEST_F(MetricsTest, ScopedTimer_MeasuresHistogram) {
  Histogram histogram;

  {
    ScopedTimer timer(histogram);
    // Simulate some work.
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  EXPECT_EQ(histogram.count(), 1u);
  EXPECT_GT(histogram.sum(), 0.0);
}

TEST_F(MetricsTest, ScopedTimer_MeasuresSummary) {
  Summary summary;

  {
    ScopedTimer timer(summary);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }

  EXPECT_EQ(summary.count(), 1u);
  EXPECT_GT(summary.sum(), 0.0);
}

TEST_F(MetricsTest, ScopedTimer_EarlyStop) {
  Histogram histogram;

  {
    ScopedTimer timer(histogram);
    auto duration = timer.stop();
    EXPECT_GT(duration.count(), 0);
    // Destructor should not record again.
  }

  EXPECT_EQ(histogram.count(), 1u);
}

// ThroughputTracker tests.

TEST_F(MetricsTest, ThroughputTracker_Record) {
  ThroughputTracker tracker(std::chrono::seconds(1), [this]() { return now(); });

  tracker.record(100);
  tracker.record(50);

  EXPECT_EQ(tracker.total(), 150u);
}

TEST_F(MetricsTest, ThroughputTracker_CalculatesThroughput) {
  ThroughputTracker tracker(std::chrono::seconds(1), [this]() { return now(); });

  tracker.record(100);
  advance_time(std::chrono::milliseconds(500));

  // After 500ms, throughput should be ~200/sec.
  EXPECT_NEAR(tracker.throughput(), 200.0, 50.0);
}

TEST_F(MetricsTest, ThroughputTracker_Reset) {
  ThroughputTracker tracker(std::chrono::seconds(1), [this]() { return now(); });

  tracker.record(100);
  tracker.reset();

  EXPECT_EQ(tracker.total(), 0u);
}

// Global registry test.

TEST_F(MetricsTest, GlobalRegistry) {
  auto& registry = get_registry();

  registry.counter("global_test").increment();
  EXPECT_EQ(get_registry().counter("global_test").value(), 1u);
}

}  // namespace veil::metrics::test
