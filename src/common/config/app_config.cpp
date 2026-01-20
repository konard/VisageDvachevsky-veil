#include "common/config/app_config.h"

#include <CLI/CLI.hpp>

#include <stdexcept>

namespace veil::config {

AppConfig parse_arguments(int argc, char** argv) {
  AppConfig config{};
  CLI::App app("VEIL base CLI options");
  app.set_help_flag("-h,--help", "Show help");

  app.add_option("-c,--config", config.config_path, "Path to configuration file");

  std::string log_level = "info";
  app.add_option("-l,--log-level", log_level,
                 "Log level (trace, debug, info, warn, error, critical, off)");

  bool log_to_stderr = false;
  app.add_flag("--log-to-stderr", log_to_stderr, "Send logs to stderr instead of stdout");

  try {
    app.parse(argc, argv);
  } catch (const CLI::ParseError& e) {
    throw std::invalid_argument(e.what());
  }

  config.log_level = logging::parse_log_level(log_level);
  config.log_to_stdout = !log_to_stderr;

  return config;
}

void apply_logging(const AppConfig& config) {
  logging::configure_logging(config.log_level, config.log_to_stdout);
}

}  // namespace veil::config
