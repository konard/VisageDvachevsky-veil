#include "tun/routing.h"

#include <array>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <ranges>
#include <sstream>
#include <system_error>

#include "common/logging/logger.h"

namespace {
constexpr const char* kIpForwardPath = "/proc/sys/net/ipv4/ip_forward";
constexpr std::size_t kCommandBufferSize = 1024;

std::error_code last_error() { return std::error_code(errno, std::generic_category()); }
}  // namespace

namespace veil::tun {

RouteManager::RouteManager() = default;

RouteManager::~RouteManager() { cleanup(); }

std::optional<std::string> RouteManager::execute_command(const std::string& command,
                                                          std::error_code& ec) {
  LOG_DEBUG("Executing: {}", command);

  std::array<char, kCommandBufferSize> buffer{};
  std::string result;

  FILE* pipe = popen(command.c_str(), "r");
  if (pipe == nullptr) {
    ec = last_error();
    LOG_ERROR("Failed to execute command: {}", ec.message());
    return std::nullopt;
  }

  while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
    result += buffer.data();
  }

  const int status = pclose(pipe);
  if (status != 0) {
    ec = std::error_code(status, std::generic_category());
    LOG_DEBUG("Command returned non-zero status: {}", status);
    // Still return output for debugging.
    return result;
  }

  return result;
}

bool RouteManager::execute_command_check(const std::string& command, std::error_code& ec) {
  auto result = execute_command(command + " 2>&1", ec);
  if (ec) {
    if (result) {
      LOG_ERROR("Command failed: {} - Output: {}", command, *result);
    }
    return false;
  }
  return true;
}

bool RouteManager::add_route(const Route& route, std::error_code& ec) {
  std::ostringstream cmd;
  cmd << "ip route add " << route.destination;

  if (!route.netmask.empty() && route.netmask != "255.255.255.255") {
    // Convert netmask to CIDR prefix length.
    // Simple conversion for common netmasks.
    int prefix = 32;
    if (route.netmask == "0.0.0.0") {
      prefix = 0;
    } else if (route.netmask == "255.0.0.0") {
      prefix = 8;
    } else if (route.netmask == "255.255.0.0") {
      prefix = 16;
    } else if (route.netmask == "255.255.255.0") {
      prefix = 24;
    } else if (route.netmask == "255.255.255.128") {
      prefix = 25;
    } else if (route.netmask == "255.255.255.192") {
      prefix = 26;
    } else if (route.netmask == "255.255.255.224") {
      prefix = 27;
    } else if (route.netmask == "255.255.255.240") {
      prefix = 28;
    } else if (route.netmask == "255.255.255.248") {
      prefix = 29;
    } else if (route.netmask == "255.255.255.252") {
      prefix = 30;
    } else if (route.netmask == "255.255.255.254") {
      prefix = 31;
    }
    cmd << "/" << prefix;
  }

  if (!route.gateway.empty()) {
    cmd << " via " << route.gateway;
  }

  if (!route.interface.empty()) {
    cmd << " dev " << route.interface;
  }

  if (route.metric > 0) {
    cmd << " metric " << route.metric;
  }

  if (!execute_command_check(cmd.str(), ec)) {
    return false;
  }

  added_routes_.push_back(route);
  LOG_INFO("Added route: {} via {} dev {}", route.destination,
           route.gateway.empty() ? "(direct)" : route.gateway, route.interface);
  return true;
}

bool RouteManager::remove_route(const Route& route, std::error_code& ec) {
  std::ostringstream cmd;
  cmd << "ip route del " << route.destination;

  if (!route.gateway.empty()) {
    cmd << " via " << route.gateway;
  }

  if (!route.interface.empty()) {
    cmd << " dev " << route.interface;
  }

  if (!execute_command_check(cmd.str(), ec)) {
    return false;
  }

  LOG_INFO("Removed route: {}", route.destination);
  return true;
}

bool RouteManager::add_default_route(const std::string& interface, const std::string& gateway,
                                      int metric, std::error_code& ec) {
  Route route;
  route.destination = "0.0.0.0/0";
  route.gateway = gateway;
  route.interface = interface;
  route.metric = metric;
  return add_route(route, ec);
}

bool RouteManager::remove_default_route(const std::string& interface, std::error_code& ec) {
  Route route;
  route.destination = "0.0.0.0/0";
  route.interface = interface;
  return remove_route(route, ec);
}

bool RouteManager::set_ip_forwarding(bool enable, std::error_code& ec) {
  // Save original state if not already saved.
  if (!forwarding_state_saved_) {
    std::error_code ignored;
    original_forwarding_state_ = is_ip_forwarding_enabled(ignored);
    forwarding_state_saved_ = true;
  }

  std::ofstream file(kIpForwardPath);
  if (!file) {
    ec = last_error();
    LOG_ERROR("Failed to open {}: {}", kIpForwardPath, ec.message());
    return false;
  }

  file << (enable ? "1" : "0");
  if (!file) {
    ec = last_error();
    LOG_ERROR("Failed to write to {}: {}", kIpForwardPath, ec.message());
    return false;
  }

  LOG_INFO("IP forwarding {}", enable ? "enabled" : "disabled");
  return true;
}

bool RouteManager::is_ip_forwarding_enabled(std::error_code& ec) {
  std::ifstream file(kIpForwardPath);
  if (!file) {
    ec = last_error();
    return false;
  }

  int value = 0;
  file >> value;
  return value == 1;
}

std::string RouteManager::build_nat_command(const NatConfig& config, bool add) {
  std::ostringstream cmd;
  cmd << "iptables -t nat ";
  cmd << (add ? "-A" : "-D");
  cmd << " POSTROUTING -o " << config.external_interface;

  if (!config.internal_interface.empty()) {
    cmd << " -s 10.8.0.0/24";  // Typical VPN subnet.
  }

  if (config.use_masquerade) {
    cmd << " -j MASQUERADE";
  } else {
    cmd << " -j SNAT --to-source " << config.snat_source;
  }

  return cmd.str();
}

bool RouteManager::configure_nat(const NatConfig& config, std::error_code& ec) {
  // Enable IP forwarding first.
  if (config.enable_forwarding) {
    if (!set_ip_forwarding(true, ec)) {
      return false;
    }
  }

  // Add iptables MASQUERADE rule.
  const std::string cmd = build_nat_command(config, true);
  if (!execute_command_check(cmd, ec)) {
    return false;
  }

  // Also add FORWARD rules for the internal interface.
  std::ostringstream forward_in;
  forward_in << "iptables -A FORWARD -i " << config.internal_interface << " -j ACCEPT";
  if (!execute_command_check(forward_in.str(), ec)) {
    LOG_WARN("Failed to add FORWARD rule for input: {}", ec.message());
    // Don't fail, NAT might still work.
  }

  std::ostringstream forward_out;
  forward_out << "iptables -A FORWARD -o " << config.internal_interface << " -j ACCEPT";
  if (!execute_command_check(forward_out.str(), ec)) {
    LOG_WARN("Failed to add FORWARD rule for output: {}", ec.message());
  }

  nat_configured_ = true;
  current_nat_config_ = config;
  LOG_INFO("NAT configured: {} -> {} ({})", config.internal_interface, config.external_interface,
           config.use_masquerade ? "MASQUERADE" : "SNAT");
  return true;
}

bool RouteManager::remove_nat(const NatConfig& config, std::error_code& ec) {
  // Remove MASQUERADE rule.
  const std::string cmd = build_nat_command(config, false);
  execute_command_check(cmd, ec);  // Ignore errors.

  // Remove FORWARD rules.
  std::ostringstream forward_in;
  forward_in << "iptables -D FORWARD -i " << config.internal_interface << " -j ACCEPT";
  execute_command_check(forward_in.str(), ec);

  std::ostringstream forward_out;
  forward_out << "iptables -D FORWARD -o " << config.internal_interface << " -j ACCEPT";
  execute_command_check(forward_out.str(), ec);

  nat_configured_ = false;
  LOG_INFO("NAT removed");
  return true;
}

std::optional<SystemState> RouteManager::get_system_state(std::error_code& ec) {
  SystemState state;
  state.ip_forwarding_enabled = is_ip_forwarding_enabled(ec);

  // Get default route info.
  auto result = execute_command("ip route show default", ec);
  if (result && !result->empty()) {
    // Parse output like: "default via 192.168.1.1 dev eth0"
    std::istringstream iss(*result);
    std::string token;
    while (iss >> token) {
      if (token == "via") {
        iss >> state.default_gateway;
      } else if (token == "dev") {
        iss >> state.default_interface;
      }
    }
  }

  return state;
}

bool RouteManager::save_routes(std::error_code& ec) {
  // Get current routing table.
  auto result = execute_command("ip route show", ec);
  if (!result) {
    return false;
  }
  LOG_DEBUG("Current routes saved:\n{}", *result);
  return true;
}

bool RouteManager::restore_routes(std::error_code& ec) {
  // Remove added routes in reverse order.
  for (auto& route : std::ranges::reverse_view(added_routes_)) {
    std::error_code ignored;
    remove_route(route, ignored);
  }
  added_routes_.clear();

  // Restore IP forwarding state.
  if (forwarding_state_saved_) {
    set_ip_forwarding(original_forwarding_state_, ec);
    forwarding_state_saved_ = false;
  }

  return true;
}

bool RouteManager::route_exists(const Route& route, std::error_code& ec) {
  std::ostringstream cmd;
  cmd << "ip route show " << route.destination;
  if (!route.interface.empty()) {
    cmd << " dev " << route.interface;
  }

  auto result = execute_command(cmd.str(), ec);
  return result && !result->empty();
}

void RouteManager::cleanup() {
  std::error_code ec;

  // Remove NAT if configured.
  if (nat_configured_) {
    remove_nat(current_nat_config_, ec);
  }

  // Restore routes.
  restore_routes(ec);
}

}  // namespace veil::tun
