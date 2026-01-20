#include "common/logging/logger.h"

#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include <algorithm>
#include <cctype>
#include <memory>
#include <stdexcept>
#include <string>

namespace {
std::string normalize_level(std::string_view value) {
  std::string normalized(value);
  std::transform(normalized.begin(), normalized.end(), normalized.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
  return normalized;
}
}  // namespace

namespace veil::logging {

LogLevel parse_log_level(std::string_view value) {
  const auto normalized = normalize_level(value);
  if (normalized == "trace") return LogLevel::trace;
  if (normalized == "debug") return LogLevel::debug;
  if (normalized == "info") return LogLevel::info;
  if (normalized == "warn" || normalized == "warning") return LogLevel::warn;
  if (normalized == "error" || normalized == "err") return LogLevel::error;
  if (normalized == "critical" || normalized == "crit") return LogLevel::critical;
  if (normalized == "off" || normalized == "none") return LogLevel::off;
  throw std::invalid_argument("Unsupported log level: " + std::string(value));
}

spdlog::level::level_enum to_spdlog_level(LogLevel level) {
  switch (level) {
    case LogLevel::trace:
      return spdlog::level::trace;
    case LogLevel::debug:
      return spdlog::level::debug;
    case LogLevel::info:
      return spdlog::level::info;
    case LogLevel::warn:
      return spdlog::level::warn;
    case LogLevel::error:
      return spdlog::level::err;
    case LogLevel::critical:
      return spdlog::level::critical;
    case LogLevel::off:
      return spdlog::level::off;
  }
  return spdlog::level::info;
}

void configure_logging(LogLevel level, bool to_stdout) {
  std::shared_ptr<spdlog::logger> logger;
  if (to_stdout) {
    logger = std::make_shared<spdlog::logger>(
        "veil", std::make_shared<spdlog::sinks::stdout_color_sink_mt>());
  } else {
    logger = std::make_shared<spdlog::logger>(
        "veil", std::make_shared<spdlog::sinks::stderr_color_sink_mt>());
  }

  logger->set_level(to_spdlog_level(level));
  logger->set_pattern("%Y-%m-%d %H:%M:%S.%e [%^%l%$] %v");
  spdlog::set_default_logger(logger);
  spdlog::flush_on(spdlog::level::err);
}

}  // namespace veil::logging
