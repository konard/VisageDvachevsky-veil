#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <vector>

#include "common/logging/logger.h"

namespace veil::logging {

// Log entry for async processing.
struct LogEntry {
  LogLevel level;
  std::string message;
  std::string location;
  std::chrono::steady_clock::time_point timestamp;
};

// Configuration for constrained logging.
struct ConstrainedLoggerConfig {
  // Log level filter.
  LogLevel min_level{LogLevel::info};
  // Maximum log entries per second (0 = unlimited).
  std::uint32_t rate_limit_per_sec{100};
  // Sampling rate for routine events (0.0 to 1.0, 1.0 = log all).
  double sampling_rate{1.0};
  // Enable async logging (non-blocking in hot path).
  bool async_logging{true};
  // Queue size for async logging.
  std::size_t async_queue_size{10000};
  // Enable structured logging (JSON format).
  bool structured_logging{false};
  // Categories to always log (bypass rate limiting).
  std::vector<std::string> priority_categories;
  // Hot path categories to apply strict rate limiting.
  std::vector<std::string> hot_path_categories;
  // Hot path rate limit (stricter than default).
  std::uint32_t hot_path_rate_limit_per_sec{10};
};

// Rate limiter for log messages.
class LogRateLimiter {
 public:
  using Clock = std::chrono::steady_clock;

  explicit LogRateLimiter(std::uint32_t max_per_sec,
                          std::function<Clock::time_point()> now_fn = Clock::now);

  // Check if a log entry should be allowed.
  bool allow();

  // Reset the rate limiter.
  void reset();

  // Get current rate.
  std::uint32_t current_rate() const { return count_in_window_.load(); }

  // Get number of dropped entries.
  std::uint64_t dropped_count() const { return dropped_.load(); }

 private:
  std::uint32_t max_per_sec_;
  std::function<Clock::time_point()> now_fn_;
  std::atomic<std::uint32_t> count_in_window_{0};
  std::atomic<std::uint64_t> dropped_{0};
  Clock::time_point window_start_;
  mutable std::mutex mutex_;
};

// Sampler for log messages.
class LogSampler {
 public:
  explicit LogSampler(double sampling_rate);

  // Check if this log entry should be sampled.
  bool sample();

  // Get sampling rate.
  double rate() const { return rate_; }

  // Get number of sampled entries.
  std::uint64_t sampled_count() const { return sampled_.load(); }

  // Get number of skipped entries.
  std::uint64_t skipped_count() const { return skipped_.load(); }

 private:
  double rate_;
  std::atomic<std::uint64_t> sampled_{0};
  std::atomic<std::uint64_t> skipped_{0};
  std::atomic<std::uint64_t> counter_{0};
};

// Async log queue.
class AsyncLogQueue {
 public:
  explicit AsyncLogQueue(std::size_t max_size);
  ~AsyncLogQueue();

  // Start the async processing thread.
  void start();

  // Stop the async processing thread.
  void stop();

  // Enqueue a log entry (non-blocking).
  // Returns false if queue is full.
  bool enqueue(LogEntry entry);

  // Set the sink function for processing entries.
  void set_sink(std::function<void(const LogEntry&)> sink);

  // Get queue size.
  std::size_t size() const;

  // Check if queue is running.
  bool is_running() const { return running_.load(); }

  // Get dropped count.
  std::uint64_t dropped_count() const { return dropped_.load(); }

 private:
  void process_loop();

  std::size_t max_size_;
  std::deque<LogEntry> queue_;
  std::function<void(const LogEntry&)> sink_;
  std::mutex mutex_;
  std::condition_variable cv_;
  std::atomic<bool> running_{false};
  std::atomic<std::uint64_t> dropped_{0};
  std::thread worker_;
};

// Structured log formatter.
class StructuredFormatter {
 public:
  // Format a log entry as JSON.
  static std::string to_json(const LogEntry& entry);

  // Format with additional context.
  static std::string to_json(const LogEntry& entry,
                             const std::unordered_map<std::string, std::string>& context);

  // Format log level as string.
  static const char* level_to_string(LogLevel level);
};

// Constrained logger with rate limiting, sampling, and async support.
class ConstrainedLogger {
 public:
  using Clock = std::chrono::steady_clock;

  explicit ConstrainedLogger(ConstrainedLoggerConfig config = {},
                             std::function<Clock::time_point()> now_fn = Clock::now);
  ~ConstrainedLogger();

  // Initialize the logger.
  void initialize();

  // Shutdown the logger.
  void shutdown();

  // Log a message.
  void log(LogLevel level, std::string_view message, std::string_view category = "",
           std::string_view location = "");

  // Log with sampling (for high-frequency events).
  void log_sampled(LogLevel level, std::string_view message, std::string_view category = "",
                   std::string_view location = "");

  // Log a structured message with context.
  void log_structured(LogLevel level, std::string_view message,
                      const std::unordered_map<std::string, std::string>& context,
                      std::string_view category = "");

  // Set log context (added to all entries).
  void set_context(const std::string& key, const std::string& value);

  // Clear log context.
  void clear_context();

  // Check if a level is enabled.
  bool is_level_enabled(LogLevel level) const;

  // Get statistics.
  struct Stats {
    std::uint64_t total_logged{0};
    std::uint64_t rate_limited{0};
    std::uint64_t sampled_out{0};
    std::uint64_t async_dropped{0};
    std::uint32_t current_rate{0};
  };
  Stats get_stats() const;

  // Get configuration.
  const ConstrainedLoggerConfig& config() const { return config_; }

  // Update configuration.
  void update_config(const ConstrainedLoggerConfig& config);

 private:
  bool should_log(LogLevel level, std::string_view category);
  bool is_priority_category(std::string_view category) const;
  bool is_hot_path_category(std::string_view category) const;
  void write_entry(const LogEntry& entry);

  ConstrainedLoggerConfig config_;
  std::function<Clock::time_point()> now_fn_;
  std::unique_ptr<LogRateLimiter> rate_limiter_;
  std::unique_ptr<LogRateLimiter> hot_path_rate_limiter_;
  std::unique_ptr<LogSampler> sampler_;
  std::unique_ptr<AsyncLogQueue> async_queue_;
  std::unordered_map<std::string, std::string> context_;
  mutable std::mutex context_mutex_;

  std::atomic<std::uint64_t> total_logged_{0};
  std::atomic<std::uint64_t> rate_limited_{0};
  std::atomic<std::uint64_t> sampled_out_{0};
};

// Global constrained logger instance.
ConstrainedLogger& get_constrained_logger();

// Initialize the global constrained logger.
void init_constrained_logger(ConstrainedLoggerConfig config);

// Convenience macros for constrained logging.
#define CLOG_TRACE(msg) \
  ::veil::logging::get_constrained_logger().log(::veil::logging::LogLevel::trace, msg)
#define CLOG_DEBUG(msg) \
  ::veil::logging::get_constrained_logger().log(::veil::logging::LogLevel::debug, msg)
#define CLOG_INFO(msg) \
  ::veil::logging::get_constrained_logger().log(::veil::logging::LogLevel::info, msg)
#define CLOG_WARN(msg) \
  ::veil::logging::get_constrained_logger().log(::veil::logging::LogLevel::warn, msg)
#define CLOG_ERROR(msg) \
  ::veil::logging::get_constrained_logger().log(::veil::logging::LogLevel::error, msg)
#define CLOG_CRITICAL(msg) \
  ::veil::logging::get_constrained_logger().log(::veil::logging::LogLevel::critical, msg)

// Sampled logging macros (for hot paths).
#define CLOG_SAMPLED(level, msg) \
  ::veil::logging::get_constrained_logger().log_sampled(level, msg)

}  // namespace veil::logging
