#pragma once

#include <string>
#include <system_error>
#include <vector>

#include "tunnel/tunnel.h"
#include "tun/routing.h"

namespace veil::server {

// Server-specific configuration.
struct ServerConfig {
  // General settings.
  std::string config_file;
  bool daemon_mode{false};
  bool verbose{false};

  // Tunnel configuration.
  tunnel::TunnelConfig tunnel;

  // NAT configuration.
  tun::NatConfig nat;

  // Session management.
  std::size_t max_clients{256};
  std::chrono::seconds session_timeout{300};
  std::chrono::seconds cleanup_interval{60};

  // Network.
  std::string listen_address{"0.0.0.0"};
  std::uint16_t listen_port{4433};

  // IP pool for clients.
  std::string ip_pool_start{"10.8.0.2"};
  std::string ip_pool_end{"10.8.0.254"};

  // Daemon settings.
  std::string pid_file{"/var/run/veil-server.pid"};
  std::string log_file;
  std::string user;
  std::string group;
};

// Parse command-line arguments into configuration.
bool parse_args(int argc, char* argv[], ServerConfig& config, std::error_code& ec);

// Load configuration from INI file.
bool load_config_file(const std::string& path, ServerConfig& config, std::error_code& ec);

// Validate configuration.
bool validate_config(const ServerConfig& config, std::string& error);

}  // namespace veil::server
