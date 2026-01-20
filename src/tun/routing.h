#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <system_error>
#include <vector>

namespace veil::tun {

// Route entry for adding/removing routes.
struct Route {
  // Destination network (e.g., "0.0.0.0" for default, "192.168.1.0").
  std::string destination;
  // Netmask (e.g., "0.0.0.0" for default, "255.255.255.0").
  std::string netmask;
  // Gateway (empty for direct routes via interface).
  std::string gateway;
  // Interface name (e.g., "veil0").
  std::string interface;
  // Metric (lower = higher priority).
  int metric{0};
};

// NAT configuration for server mode.
struct NatConfig {
  // Interface to masquerade traffic from (e.g., "veil0").
  std::string internal_interface;
  // Interface to masquerade traffic to (e.g., "eth0").
  std::string external_interface;
  // VPN subnet in CIDR notation (e.g., "10.8.0.0/24").
  std::string vpn_subnet{"10.8.0.0/24"};
  // Enable IP forwarding.
  bool enable_forwarding{true};
  // Use iptables MASQUERADE (true) or SNAT (false).
  bool use_masquerade{true};
  // SNAT source IP (only used if use_masquerade is false).
  std::string snat_source;
};

// Result of checking system state.
struct SystemState {
  bool ip_forwarding_enabled{false};
  std::string default_interface;
  std::string default_gateway;
};

// Manages routing table entries and NAT configuration.
// Uses system commands (ip route, iptables) for configuration.
class RouteManager {
 public:
  RouteManager();
  ~RouteManager();

  // Non-copyable, non-movable.
  RouteManager(const RouteManager&) = delete;
  RouteManager& operator=(const RouteManager&) = delete;
  RouteManager(RouteManager&&) = delete;
  RouteManager& operator=(RouteManager&&) = delete;

  // Add a route to the routing table.
  bool add_route(const Route& route, std::error_code& ec);

  // Remove a route from the routing table.
  bool remove_route(const Route& route, std::error_code& ec);

  // Add default route via a specific interface.
  bool add_default_route(const std::string& interface, const std::string& gateway, int metric,
                         std::error_code& ec);

  // Remove default route via a specific interface.
  bool remove_default_route(const std::string& interface, std::error_code& ec);

  // Enable/disable IP forwarding.
  bool set_ip_forwarding(bool enable, std::error_code& ec);

  // Check if IP forwarding is enabled.
  bool is_ip_forwarding_enabled(std::error_code& ec);

  // Configure NAT (masquerading) for server mode.
  bool configure_nat(const NatConfig& config, std::error_code& ec);

  // Remove NAT configuration.
  bool remove_nat(const NatConfig& config, std::error_code& ec);

  // Get current system state (forwarding, default route).
  std::optional<SystemState> get_system_state(std::error_code& ec);

  // Save current routing table for later restoration.
  bool save_routes(std::error_code& ec);

  // Restore previously saved routes.
  bool restore_routes(std::error_code& ec);

  // Check if a route exists.
  bool route_exists(const Route& route, std::error_code& ec);

  // Remove all routes added by this manager.
  void cleanup();

 private:
  // Execute a shell command and return output.
  std::optional<std::string> execute_command(const std::string& command, std::error_code& ec);

  // Execute a command and check for success.
  bool execute_command_check(const std::string& command, std::error_code& ec);

  // Check if a command-line tool is available.
  bool is_tool_available(const std::string& tool, std::error_code& ec);

  // Check if iptables or nftables is available.
  bool check_firewall_availability(std::error_code& ec);

  // Log current iptables state for debugging.
  void log_iptables_state(const std::string& phase);

  // Build iptables command for NAT.
  std::string build_nat_command(const NatConfig& config, bool add);

  // Track added routes for cleanup.
  std::vector<Route> added_routes_;

  // Track if NAT was configured.
  bool nat_configured_{false};
  NatConfig current_nat_config_;

  // Track original IP forwarding state.
  bool original_forwarding_state_{false};
  bool forwarding_state_saved_{false};
};

}  // namespace veil::tun
