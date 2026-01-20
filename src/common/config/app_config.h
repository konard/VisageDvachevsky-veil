#pragma once

#include <string>

#include "common/logging/logger.h"

namespace veil::config {

struct AppConfig {
  std::string config_path;
  logging::LogLevel log_level{logging::LogLevel::info};
  bool log_to_stdout{true};
};

AppConfig parse_arguments(int argc, char** argv);
void apply_logging(const AppConfig& config);

}  // namespace veil::config
