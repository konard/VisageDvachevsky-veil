#include <cstdlib>
#include <iostream>

#include <spdlog/spdlog.h>

#include "client/client_config.h"
#include "common/daemon/daemon.h"
#include "common/logging/logger.h"
#include "common/signal/signal_handler.h"
#include "tunnel/tunnel.h"
#include "tun/routing.h"

using namespace veil;

namespace {
// Helper functions to avoid LOG_* macros in lambdas (clang-tidy bugprone-lambda-function-name).
void log_state_change(tunnel::ConnectionState old_state, tunnel::ConnectionState new_state) {
  const char* state_names[] = {"Disconnected", "Connecting", "Handshaking", "Connected",
                                "Reconnecting"};
  LOG_INFO("State changed: {} -> {}", state_names[static_cast<int>(old_state)],
           state_names[static_cast<int>(new_state)]);
}

void log_tunnel_error(const std::string& error) {
  LOG_ERROR("Tunnel error: {}", error);
}

void log_signal_sigint() {
  LOG_INFO("Received SIGINT, shutting down...");
}

void log_signal_sigterm() {
  LOG_INFO("Received SIGTERM, shutting down...");
}
}  // namespace

int main(int argc, char* argv[]) {
  // Parse configuration.
  client::ClientConfig config;
  std::error_code ec;

  if (!client::parse_args(argc, argv, config, ec)) {
    std::cerr << "Failed to parse arguments: " << ec.message() << '\n';
    return EXIT_FAILURE;
  }

  // Validate configuration.
  std::string validation_error;
  if (!client::validate_config(config, validation_error)) {
    std::cerr << "Configuration error: " << validation_error << '\n';
    return EXIT_FAILURE;
  }

  // Initialize logging.
  logging::configure_logging(config.verbose ? logging::LogLevel::debug : logging::LogLevel::info, true);
  LOG_INFO("VEIL Client starting...");

  // Check if already running.
  if (!config.pid_file.empty() && daemon::is_already_running(config.pid_file, ec)) {
    LOG_ERROR("Another instance is already running (PID file: {})", config.pid_file);
    return EXIT_FAILURE;
  }

  // Daemonize if requested.
  if (config.daemon_mode) {
    daemon::DaemonConfig daemon_config;
    daemon_config.pid_file = config.pid_file;
    daemon_config.user = config.user;
    daemon_config.group = config.group;

    LOG_INFO("Daemonizing...");
    if (!daemon::daemonize(daemon_config, ec)) {
      LOG_ERROR("Failed to daemonize: {}", ec.message());
      return EXIT_FAILURE;
    }
  }

  // Create PID file if not daemonizing (daemonize() creates it).
  std::unique_ptr<daemon::PidFile> pid_file;
  if (!config.daemon_mode && !config.pid_file.empty()) {
    pid_file = std::make_unique<daemon::PidFile>(config.pid_file);
    if (!pid_file->create(ec)) {
      LOG_WARN("Failed to create PID file: {}", ec.message());
    }
  }

  // Create tunnel.
  tunnel::Tunnel tun(config.tunnel);

  // Setup callbacks.
  tun.on_state_change([](tunnel::ConnectionState old_state, tunnel::ConnectionState new_state) {
    log_state_change(old_state, new_state);
  });

  tun.on_error([](const std::string& error) { log_tunnel_error(error); });

  // Initialize tunnel.
  if (!tun.initialize(ec)) {
    LOG_ERROR("Failed to initialize tunnel: {}", ec.message());
    return EXIT_FAILURE;
  }

  // Setup routing.
  auto* route_manager = tun.route_manager();

  // Add custom routes.
  for (const auto& route_str : config.routes) {
    tun::Route route;
    // Parse CIDR notation (e.g., "192.168.1.0/24").
    auto slash_pos = route_str.find('/');
    if (slash_pos != std::string::npos) {
      route.destination = route_str;  // Keep CIDR notation for ip route.
    } else {
      route.destination = route_str;
      route.netmask = "255.255.255.255";
    }
    route.interface = tun.tun_device()->device_name();

    if (!route_manager->add_route(route, ec)) {
      LOG_WARN("Failed to add route {}: {}", route_str, ec.message());
    }
  }

  // Set default route if requested.
  if (config.set_default_route) {
    // Get current default gateway first for bypass route.
    auto state = route_manager->get_system_state(ec);
    if (state && !state->default_gateway.empty()) {
      // Add bypass route for server address via original gateway.
      tun::Route bypass;
      bypass.destination = config.tunnel.server_address;
      bypass.netmask = "255.255.255.255";
      bypass.gateway = state->default_gateway;
      bypass.interface = state->default_interface;
      if (!route_manager->add_route(bypass, ec)) {
        LOG_WARN("Failed to add server bypass route: {}", ec.message());
      }
    }

    // Add default route via tunnel.
    if (!route_manager->add_default_route(tun.tun_device()->device_name(), "", 100, ec)) {
      LOG_WARN("Failed to set default route: {}", ec.message());
    }
  }

  // Setup signal handlers.
  auto& sig_handler = signal::SignalHandler::instance();
  sig_handler.on(signal::Signal::kInterrupt, [&tun](signal::Signal) {
    log_signal_sigint();
    tun.stop();
  });
  sig_handler.on(signal::Signal::kTerminate, [&tun](signal::Signal) {
    log_signal_sigterm();
    tun.stop();
  });

  // Run the tunnel.
  LOG_INFO("Starting tunnel to {}:{}", config.tunnel.server_address, config.tunnel.server_port);
  tun.run();

  // Cleanup routes.
  route_manager->cleanup();

  LOG_INFO("VEIL Client stopped");
  return EXIT_SUCCESS;
}
