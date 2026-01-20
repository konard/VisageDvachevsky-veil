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
  // Check if ip command is available.
  if (!is_tool_available("ip", ec)) {
    ec = std::make_error_code(std::errc::no_such_file_or_directory);
    LOG_ERROR("Cannot add route: ip command not available");
    return false;
  }

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

bool RouteManager::is_tool_available(const std::string& tool, std::error_code& ec) {
  std::ostringstream cmd;
  cmd << "command -v " << tool << " >/dev/null 2>&1";
  auto result = execute_command(cmd.str(), ec);
  // command -v returns 0 if tool exists, non-zero otherwise
  return result.has_value() && !ec;
}

bool RouteManager::check_firewall_availability(std::error_code& ec) {
  // Check for iptables first (most common)
  if (is_tool_available("iptables", ec)) {
    LOG_DEBUG("iptables is available");
    return true;
  }

  // Check for nftables as fallback
  if (is_tool_available("nft", ec)) {
    LOG_WARN("nftables (nft) is available but iptables is not - iptables commands may fail");
    LOG_WARN("Consider installing iptables-nft or iptables-legacy for compatibility");
    return false;
  }

  LOG_ERROR("Neither iptables nor nftables (nft) is available on this system");
  return false;
}

void RouteManager::log_iptables_state(const std::string& phase) {
  std::error_code ec;

  (void)phase;  // Used in LOG_DEBUG which may be compiled out
  LOG_DEBUG("=== iptables state {} ===", phase);

  // Log NAT table POSTROUTING chain
  auto nat_result = execute_command("iptables -t nat -L POSTROUTING -n -v 2>&1", ec);
  if (nat_result) {
    LOG_DEBUG("NAT POSTROUTING:\n{}", *nat_result);
  }

  // Log FORWARD chain
  auto forward_result = execute_command("iptables -L FORWARD -n -v 2>&1", ec);
  if (forward_result) {
    LOG_DEBUG("FORWARD chain:\n{}", *forward_result);
  }
}

std::string RouteManager::build_nat_command(const NatConfig& config, bool add) {
  std::ostringstream cmd;
  cmd << "iptables -t nat ";
  cmd << (add ? "-A" : "-D");
  cmd << " POSTROUTING -o " << config.external_interface;

  if (!config.internal_interface.empty() && !config.vpn_subnet.empty()) {
    cmd << " -s " << config.vpn_subnet;
  }

  if (config.use_masquerade) {
    cmd << " -j MASQUERADE";
  } else {
    cmd << " -j SNAT --to-source " << config.snat_source;
  }

  return cmd.str();
}

bool RouteManager::configure_nat(const NatConfig& config, std::error_code& ec) {
  // Check if iptables is available before proceeding.
  if (!check_firewall_availability(ec)) {
    ec = std::make_error_code(std::errc::no_such_file_or_directory);
    LOG_ERROR("Cannot configure NAT: iptables not available");
    return false;
  }

  // Log state before modifications.
  log_iptables_state("before NAT configuration");

  // Track what we've successfully added for rollback if needed.
  bool forwarding_enabled = false;

  // Enable IP forwarding first.
  if (config.enable_forwarding) {
    if (!set_ip_forwarding(true, ec)) {
      LOG_ERROR("Failed to enable IP forwarding: {}", ec.message());
      return false;
    }
    forwarding_enabled = true;
  }

  // Add iptables MASQUERADE/SNAT rule.
  const std::string nat_cmd = build_nat_command(config, true);
  if (!execute_command_check(nat_cmd, ec)) {
    LOG_ERROR("Failed to add NAT rule: {}", ec.message());
    // Rollback IP forwarding if we enabled it.
    if (forwarding_enabled && forwarding_state_saved_) {
      std::error_code rollback_ec;
      set_ip_forwarding(original_forwarding_state_, rollback_ec);
    }
    return false;
  }

  // Add FORWARD rule for incoming traffic.
  std::ostringstream forward_in;
  forward_in << "iptables -A FORWARD -i " << config.internal_interface << " -j ACCEPT";
  if (!execute_command_check(forward_in.str(), ec)) {
    LOG_ERROR("Failed to add FORWARD rule for input: {}", ec.message());
    // Rollback: remove NAT rule.
    std::error_code rollback_ec;
    const std::string remove_nat_cmd = build_nat_command(config, false);
    execute_command_check(remove_nat_cmd, rollback_ec);
    if (forwarding_enabled && forwarding_state_saved_) {
      set_ip_forwarding(original_forwarding_state_, rollback_ec);
    }
    return false;
  }

  // Add FORWARD rule for outgoing traffic.
  std::ostringstream forward_out;
  forward_out << "iptables -A FORWARD -o " << config.internal_interface << " -j ACCEPT";
  if (!execute_command_check(forward_out.str(), ec)) {
    LOG_ERROR("Failed to add FORWARD rule for output: {}", ec.message());
    // Rollback: remove all previously added rules.
    std::error_code rollback_ec;
    std::ostringstream remove_forward_in;
    remove_forward_in << "iptables -D FORWARD -i " << config.internal_interface << " -j ACCEPT";
    execute_command_check(remove_forward_in.str(), rollback_ec);
    const std::string remove_nat_cmd = build_nat_command(config, false);
    execute_command_check(remove_nat_cmd, rollback_ec);
    if (forwarding_enabled && forwarding_state_saved_) {
      set_ip_forwarding(original_forwarding_state_, rollback_ec);
    }
    return false;
  }

  // All rules added successfully.
  nat_configured_ = true;
  current_nat_config_ = config;

  // Log state after modifications.
  log_iptables_state("after NAT configuration");

  LOG_INFO("NAT configured: {} -> {} (subnet: {}, mode: {})", config.internal_interface,
           config.external_interface, config.vpn_subnet,
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
