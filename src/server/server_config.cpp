#include "server/server_config.h"

#include <fstream>
#include <sstream>

#include <CLI/CLI.hpp>

#include "common/logging/logger.h"

namespace veil::server {

namespace {
bool parse_ini_value(const std::string& line, std::string& key, std::string& value) {
  if (line.empty() || line[0] == '#' || line[0] == ';') {
    return false;
  }
  if (line[0] == '[') {
    return false;
  }

  auto pos = line.find('=');
  if (pos == std::string::npos) {
    return false;
  }

  key = line.substr(0, pos);
  value = line.substr(pos + 1);

  while (!key.empty() && (key.back() == ' ' || key.back() == '\t')) {
    key.pop_back();
  }
  while (!key.empty() && (key.front() == ' ' || key.front() == '\t')) {
    key.erase(0, 1);
  }
  while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
    value.pop_back();
  }
  while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
    value.erase(0, 1);
  }

  return !key.empty();
}

std::string get_current_section(const std::string& line) {
  if (line.size() >= 2 && line.front() == '[' && line.back() == ']') {
    return line.substr(1, line.size() - 2);
  }
  return "";
}
}  // namespace

bool parse_args(int argc, char* argv[], ServerConfig& config, std::error_code& ec) {
  CLI::App app{"VEIL VPN Server"};

  // General options.
  app.add_option("-c,--config", config.config_file, "Configuration file path");
  app.add_flag("-d,--daemon", config.daemon_mode, "Run as daemon");
  app.add_flag("-v,--verbose", config.verbose, "Enable verbose logging");

  // Network.
  app.add_option("-l,--listen", config.listen_address, "Listen address")->default_val("0.0.0.0");
  app.add_option("-p,--port", config.listen_port, "Listen port")->default_val(4433);

  // TUN device.
  app.add_option("--tun-name", config.tunnel.tun.device_name, "TUN device name")->default_val("veil0");
  app.add_option("--tun-ip", config.tunnel.tun.ip_address, "TUN device IP address")
      ->default_val("10.8.0.1");
  app.add_option("--tun-netmask", config.tunnel.tun.netmask, "TUN device netmask")
      ->default_val("255.255.255.0");
  app.add_option("--mtu", config.tunnel.tun.mtu, "MTU size")->default_val(1400);

  // Crypto.
  app.add_option("-k,--key", config.tunnel.key_file, "Pre-shared key file");
  app.add_option("--obfuscation-seed", config.tunnel.obfuscation_seed_file, "Obfuscation seed file");

  // NAT.
  app.add_option("--external-interface", config.nat.external_interface, "External interface for NAT")
      ->default_val("eth0");
  app.add_flag("--enable-nat", config.nat.enable_forwarding, "Enable NAT/masquerading")
      ->default_val(true);

  // Session management.
  app.add_option("--max-clients", config.max_clients, "Maximum number of clients")->default_val(256);
  int session_timeout_seconds = 300;
  app.add_option("--session-timeout", session_timeout_seconds, "Session timeout in seconds")
      ->default_val(300);

  // IP pool.
  app.add_option("--ip-pool-start", config.ip_pool_start, "IP pool start")->default_val("10.8.0.2");
  app.add_option("--ip-pool-end", config.ip_pool_end, "IP pool end")->default_val("10.8.0.254");

  // Daemon settings.
  app.add_option("--pid-file", config.pid_file, "PID file path");
  app.add_option("--log-file", config.log_file, "Log file path");
  app.add_option("--user", config.user, "Run as user");
  app.add_option("--group", config.group, "Run as group");

  try {
    app.parse(argc, argv);
  } catch (const CLI::ParseError& e) {
    ec = std::make_error_code(std::errc::invalid_argument);
    return false;
  }

  // Load config file if specified.
  if (!config.config_file.empty()) {
    if (!load_config_file(config.config_file, config, ec)) {
      return false;
    }
  }

  // Convert session timeout.
  config.session_timeout = std::chrono::seconds(session_timeout_seconds);

  // Set up tunnel config.
  config.tunnel.local_port = config.listen_port;
  config.tunnel.verbose = config.verbose;

  // Set up NAT config.
  config.nat.internal_interface = config.tunnel.tun.device_name;

  return true;
}

bool load_config_file(const std::string& path, ServerConfig& config, std::error_code& ec) {
  std::ifstream file(path);
  if (!file) {
    ec = std::error_code(errno, std::generic_category());
    LOG_ERROR("Failed to open config file: {}", path);
    return false;
  }

  std::string line;
  std::string section;

  while (std::getline(file, line)) {
    std::string new_section = get_current_section(line);
    if (!new_section.empty()) {
      section = new_section;
      continue;
    }

    std::string key;
    std::string value;
    if (!parse_ini_value(line, key, value)) {
      continue;
    }

    if (section == "server" || section.empty()) {
      if (key == "listen_address") {
        config.listen_address = value;
      } else if (key == "listen_port") {
        config.listen_port = static_cast<std::uint16_t>(std::stoi(value));
      } else if (key == "daemon") {
        config.daemon_mode = (value == "true" || value == "1" || value == "yes");
      } else if (key == "verbose") {
        config.verbose = (value == "true" || value == "1" || value == "yes");
      }
    } else if (section == "tun") {
      if (key == "device_name") {
        config.tunnel.tun.device_name = value;
      } else if (key == "ip_address") {
        config.tunnel.tun.ip_address = value;
      } else if (key == "netmask") {
        config.tunnel.tun.netmask = value;
      } else if (key == "mtu") {
        config.tunnel.tun.mtu = std::stoi(value);
      }
    } else if (section == "crypto") {
      if (key == "preshared_key_file") {
        config.tunnel.key_file = value;
      }
    } else if (section == "obfuscation") {
      if (key == "profile_seed_file") {
        config.tunnel.obfuscation_seed_file = value;
      }
    } else if (section == "nat") {
      if (key == "external_interface") {
        config.nat.external_interface = value;
      } else if (key == "enable_forwarding") {
        config.nat.enable_forwarding = (value == "true" || value == "1" || value == "yes");
      } else if (key == "use_masquerade") {
        config.nat.use_masquerade = (value == "true" || value == "1" || value == "yes");
      } else if (key == "snat_source") {
        config.nat.snat_source = value;
      }
    } else if (section == "sessions") {
      if (key == "max_clients") {
        config.max_clients = std::stoul(value);
      } else if (key == "session_timeout") {
        config.session_timeout = std::chrono::seconds(std::stoi(value));
      } else if (key == "cleanup_interval") {
        config.cleanup_interval = std::chrono::seconds(std::stoi(value));
      }
    } else if (section == "ip_pool") {
      if (key == "start") {
        config.ip_pool_start = value;
      } else if (key == "end") {
        config.ip_pool_end = value;
      }
    } else if (section == "daemon") {
      if (key == "pid_file") {
        config.pid_file = value;
      } else if (key == "log_file") {
        config.log_file = value;
      } else if (key == "user") {
        config.user = value;
      } else if (key == "group") {
        config.group = value;
      }
    }
  }

  LOG_DEBUG("Loaded configuration from {}", path);
  return true;
}

bool validate_config(const ServerConfig& config, std::string& error) {
  if (config.listen_port == 0) {
    error = "Invalid listen port";
    return false;
  }

  if (config.tunnel.tun.ip_address.empty()) {
    error = "TUN IP address is required";
    return false;
  }

  if (config.tunnel.tun.mtu < 576 || config.tunnel.tun.mtu > 65535) {
    error = "MTU must be between 576 and 65535";
    return false;
  }

  if (config.max_clients == 0) {
    error = "Max clients must be greater than 0";
    return false;
  }

  return true;
}

}  // namespace veil::server
