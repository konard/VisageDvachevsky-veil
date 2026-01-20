#pragma once

#include <spdlog/common.h>
#include <spdlog/spdlog.h>

#include <string_view>

namespace veil::logging {

enum class LogLevel {
  trace,
  debug,
  info,
  warn,
  error,
  critical,
  off
};

LogLevel parse_log_level(std::string_view value);
spdlog::level::level_enum to_spdlog_level(LogLevel level);
void configure_logging(LogLevel level, bool to_stdout);

}  // namespace veil::logging

// Logging macros for convenience.
#define LOG_TRACE(...) SPDLOG_TRACE(__VA_ARGS__)
#define LOG_DEBUG(...) SPDLOG_DEBUG(__VA_ARGS__)
#define LOG_INFO(...) SPDLOG_INFO(__VA_ARGS__)
#define LOG_WARN(...) SPDLOG_WARN(__VA_ARGS__)
#define LOG_ERROR(...) SPDLOG_ERROR(__VA_ARGS__)
#define LOG_CRITICAL(...) SPDLOG_CRITICAL(__VA_ARGS__)
