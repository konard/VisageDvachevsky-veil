#include "common/logging/constrained_logger.h"

#include <algorithm>
#include <iomanip>
#include <random>
#include <sstream>

namespace veil::logging {

// LogRateLimiter implementation.

LogRateLimiter::LogRateLimiter(std::uint32_t max_per_sec, std::function<Clock::time_point()> now_fn)
    : max_per_sec_(max_per_sec), now_fn_(std::move(now_fn)), window_start_(now_fn_()) {}

bool LogRateLimiter::allow() {
  if (max_per_sec_ == 0) {
    return true;  // Unlimited.
  }

  std::lock_guard<std::mutex> lock(mutex_);

  auto now = now_fn_();
  auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - window_start_);

  // Reset window if a second has passed.
  if (elapsed >= std::chrono::seconds(1)) {
    window_start_ = now;
    count_in_window_.store(0);
  }

  if (count_in_window_.load() >= max_per_sec_) {
    dropped_++;
    return false;
  }

  count_in_window_++;
  return true;
}

void LogRateLimiter::reset() {
  std::lock_guard<std::mutex> lock(mutex_);
  window_start_ = now_fn_();
  count_in_window_.store(0);
  dropped_.store(0);
}

// LogSampler implementation.

LogSampler::LogSampler(double sampling_rate) : rate_(std::clamp(sampling_rate, 0.0, 1.0)) {}

bool LogSampler::sample() {
  if (rate_ >= 1.0) {
    sampled_++;
    return true;
  }
  if (rate_ <= 0.0) {
    skipped_++;
    return false;
  }

  // Use counter-based sampling for determinism.
  auto count = counter_.fetch_add(1);
  auto threshold = static_cast<std::uint64_t>(1.0 / rate_);

  if (count % threshold == 0) {
    sampled_++;
    return true;
  }

  skipped_++;
  return false;
}

// AsyncLogQueue implementation.

AsyncLogQueue::AsyncLogQueue(std::size_t max_size) : max_size_(max_size) {}

AsyncLogQueue::~AsyncLogQueue() {
  stop();
}

void AsyncLogQueue::start() {
  if (running_.load()) {
    return;
  }

  running_.store(true);
  worker_ = std::thread(&AsyncLogQueue::process_loop, this);
}

void AsyncLogQueue::stop() {
  if (!running_.load()) {
    return;
  }

  running_.store(false);
  cv_.notify_all();

  if (worker_.joinable()) {
    worker_.join();
  }
}

bool AsyncLogQueue::enqueue(LogEntry entry) {
  std::lock_guard<std::mutex> lock(mutex_);

  if (queue_.size() >= max_size_) {
    dropped_++;
    return false;
  }

  queue_.push_back(std::move(entry));
  cv_.notify_one();
  return true;
}

void AsyncLogQueue::set_sink(std::function<void(const LogEntry&)> sink) {
  sink_ = std::move(sink);
}

std::size_t AsyncLogQueue::size() const {
  std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mutex_));
  return queue_.size();
}

void AsyncLogQueue::process_loop() {
  while (running_.load()) {
    LogEntry entry;
    bool has_entry = false;

    {
      std::unique_lock<std::mutex> lock(mutex_);
      cv_.wait_for(lock, std::chrono::milliseconds(100),
                   [this] { return !queue_.empty() || !running_.load(); });

      if (!queue_.empty()) {
        entry = std::move(queue_.front());
        queue_.pop_front();
        has_entry = true;
      }
    }

    if (has_entry && sink_) {
      sink_(entry);
    }
  }

  // Drain remaining entries on shutdown.
  std::lock_guard<std::mutex> lock(mutex_);
  while (!queue_.empty() && sink_) {
    sink_(queue_.front());
    queue_.pop_front();
  }
}

// StructuredFormatter implementation.

std::string StructuredFormatter::to_json(const LogEntry& entry) {
  return to_json(entry, {});
}

std::string StructuredFormatter::to_json(
    const LogEntry& entry, const std::unordered_map<std::string, std::string>& context) {
  std::ostringstream oss;
  oss << "{";
  oss << R"("timestamp":)" << std::chrono::duration_cast<std::chrono::milliseconds>(
                                 entry.timestamp.time_since_epoch())
                                 .count();
  oss << R"(,"level":")" << level_to_string(entry.level) << "\"";
  oss << R"(,"message":")";

  // Escape message for JSON.
  for (char c : entry.message) {
    switch (c) {
      case '"':
        oss << "\\\"";
        break;
      case '\\':
        oss << "\\\\";
        break;
      case '\n':
        oss << "\\n";
        break;
      case '\r':
        oss << "\\r";
        break;
      case '\t':
        oss << "\\t";
        break;
      default:
        oss << c;
    }
  }
  oss << "\"";

  if (!entry.location.empty()) {
    oss << R"(,"location":")" << entry.location << "\"";
  }

  for (const auto& [key, value] : context) {
    oss << ",\"" << key << "\":\"" << value << "\"";
  }

  oss << "}";
  return oss.str();
}

const char* StructuredFormatter::level_to_string(LogLevel level) {
  switch (level) {
    case LogLevel::trace:
      return "trace";
    case LogLevel::debug:
      return "debug";
    case LogLevel::info:
      return "info";
    case LogLevel::warn:
      return "warn";
    case LogLevel::error:
      return "error";
    case LogLevel::critical:
      return "critical";
    case LogLevel::off:
      return "off";
    default:
      return "unknown";
  }
}

// ConstrainedLogger implementation.

ConstrainedLogger::ConstrainedLogger(ConstrainedLoggerConfig config,
                                     std::function<Clock::time_point()> now_fn)
    : config_(std::move(config)), now_fn_(std::move(now_fn)) {
  rate_limiter_ = std::make_unique<LogRateLimiter>(config_.rate_limit_per_sec, now_fn_);
  hot_path_rate_limiter_ =
      std::make_unique<LogRateLimiter>(config_.hot_path_rate_limit_per_sec, now_fn_);
  sampler_ = std::make_unique<LogSampler>(config_.sampling_rate);

  if (config_.async_logging) {
    async_queue_ = std::make_unique<AsyncLogQueue>(config_.async_queue_size);
    async_queue_->set_sink([this](const LogEntry& entry) { write_entry(entry); });
  }
}

ConstrainedLogger::~ConstrainedLogger() {
  shutdown();
}

void ConstrainedLogger::initialize() {
  if (async_queue_) {
    async_queue_->start();
  }
}

void ConstrainedLogger::shutdown() {
  if (async_queue_) {
    async_queue_->stop();
  }
}

void ConstrainedLogger::log(LogLevel level, std::string_view message, std::string_view category,
                            std::string_view location) {
  if (!should_log(level, category)) {
    return;
  }

  LogEntry entry;
  entry.level = level;
  entry.message = std::string(message);
  entry.location = std::string(location);
  entry.timestamp = now_fn_();

  total_logged_++;

  if (async_queue_ && async_queue_->is_running()) {
    // Make a copy for fallback before moving.
    LogEntry entry_copy = entry;
    if (!async_queue_->enqueue(std::move(entry_copy))) {
      // Queue full, log synchronously as fallback.
      write_entry(entry);
    }
  } else {
    write_entry(entry);
  }
}

void ConstrainedLogger::log_sampled(LogLevel level, std::string_view message,
                                    std::string_view category, std::string_view location) {
  if (!sampler_->sample()) {
    sampled_out_++;
    return;
  }

  log(level, message, category, location);
}

void ConstrainedLogger::log_structured(LogLevel level, std::string_view message,
                                        const std::unordered_map<std::string, std::string>& context,
                                        std::string_view category) {
  if (!should_log(level, category)) {
    return;
  }

  LogEntry entry;
  entry.level = level;
  entry.timestamp = now_fn_();

  // Merge context with global context.
  auto merged_context = context;
  {
    std::lock_guard<std::mutex> lock(context_mutex_);
    for (const auto& [key, value] : context_) {
      if (merged_context.find(key) == merged_context.end()) {
        merged_context[key] = value;
      }
    }
  }

  entry.message = std::string(message);

  total_logged_++;

  if (async_queue_ && async_queue_->is_running()) {
    async_queue_->enqueue(std::move(entry));
  } else {
    write_entry(entry);
  }
}

void ConstrainedLogger::set_context(const std::string& key, const std::string& value) {
  std::lock_guard<std::mutex> lock(context_mutex_);
  context_[key] = value;
}

void ConstrainedLogger::clear_context() {
  std::lock_guard<std::mutex> lock(context_mutex_);
  context_.clear();
}

bool ConstrainedLogger::is_level_enabled(LogLevel level) const {
  return level >= config_.min_level && level != LogLevel::off;
}

ConstrainedLogger::Stats ConstrainedLogger::get_stats() const {
  Stats stats;
  stats.total_logged = total_logged_.load();
  stats.rate_limited = rate_limited_.load();
  stats.sampled_out = sampled_out_.load();
  stats.async_dropped = async_queue_ ? async_queue_->dropped_count() : 0;
  stats.current_rate = rate_limiter_->current_rate();
  return stats;
}

void ConstrainedLogger::update_config(const ConstrainedLoggerConfig& config) {
  config_ = config;
  rate_limiter_ = std::make_unique<LogRateLimiter>(config_.rate_limit_per_sec, now_fn_);
  hot_path_rate_limiter_ =
      std::make_unique<LogRateLimiter>(config_.hot_path_rate_limit_per_sec, now_fn_);
  sampler_ = std::make_unique<LogSampler>(config_.sampling_rate);
}

bool ConstrainedLogger::should_log(LogLevel level, std::string_view category) {
  // Check level.
  if (!is_level_enabled(level)) {
    return false;
  }

  // Priority categories bypass rate limiting.
  if (is_priority_category(category)) {
    return true;
  }

  // Hot path categories use stricter rate limiting.
  LogRateLimiter* limiter =
      is_hot_path_category(category) ? hot_path_rate_limiter_.get() : rate_limiter_.get();

  if (!limiter->allow()) {
    rate_limited_++;
    return false;
  }

  return true;
}

bool ConstrainedLogger::is_priority_category(std::string_view category) const {
  return std::find(config_.priority_categories.begin(), config_.priority_categories.end(),
                   category) != config_.priority_categories.end();
}

bool ConstrainedLogger::is_hot_path_category(std::string_view category) const {
  return std::find(config_.hot_path_categories.begin(), config_.hot_path_categories.end(),
                   category) != config_.hot_path_categories.end();
}

void ConstrainedLogger::write_entry(const LogEntry& entry) {
  std::string formatted;

  if (config_.structured_logging) {
    std::lock_guard<std::mutex> lock(context_mutex_);
    formatted = StructuredFormatter::to_json(entry, context_);
  } else {
    formatted = entry.message;
  }

  // Write to spdlog.
  switch (entry.level) {
    case LogLevel::trace:
    case LogLevel::debug:
      LOG_DEBUG("{}", formatted);
      break;
    case LogLevel::info:
      LOG_INFO("{}", formatted);
      break;
    case LogLevel::warn:
      LOG_WARN("{}", formatted);
      break;
    case LogLevel::error:
      LOG_ERROR("{}", formatted);
      break;
    case LogLevel::critical:
      LOG_CRITICAL("{}", formatted);
      break;
    case LogLevel::off:
    default:
      break;
  }
}

// Global logger instance.

static std::unique_ptr<ConstrainedLogger> g_constrained_logger;
static std::once_flag g_logger_init_flag;

ConstrainedLogger& get_constrained_logger() {
  std::call_once(g_logger_init_flag, []() {
    if (!g_constrained_logger) {
      g_constrained_logger = std::make_unique<ConstrainedLogger>();
      g_constrained_logger->initialize();
    }
  });
  return *g_constrained_logger;
}

void init_constrained_logger(ConstrainedLoggerConfig config) {
  g_constrained_logger = std::make_unique<ConstrainedLogger>(std::move(config));
  g_constrained_logger->initialize();
}

}  // namespace veil::logging
