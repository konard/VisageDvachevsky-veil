#pragma once

#include <string>
#include <system_error>

#include "tunnel/tunnel.h"

namespace veil::client {

// Client-specific configuration.
struct ClientConfig {
  // General settings.
  std::string config_file;
  bool daemon_mode{false};
  bool verbose{false};

  // Tunnel configuration.
  tunnel::TunnelConfig tunnel;

  // Routing.
  bool set_default_route{false};
  std::vector<std::string> routes;  // Additional routes to add.

  // Daemon settings.
  std::string pid_file{"/var/run/veil-client.pid"};
  std::string log_file;
  std::string user;
  std::string group;
};

// Parse command-line arguments into configuration.
bool parse_args(int argc, char* argv[], ClientConfig& config, std::error_code& ec);

// Load configuration from INI file.
bool load_config_file(const std::string& path, ClientConfig& config, std::error_code& ec);

// Validate configuration.
bool validate_config(const ClientConfig& config, std::string& error);

}  // namespace veil::client
