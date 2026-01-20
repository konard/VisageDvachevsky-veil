#include <arpa/inet.h>

#include <array>
#include <cstdlib>
#include <fstream>
#include <iostream>

#include "common/crypto/crypto_engine.h"
#include "common/daemon/daemon.h"
#include "common/handshake/handshake_processor.h"
#include "common/logging/logger.h"
#include "common/signal/signal_handler.h"
#include "common/utils/rate_limiter.h"
#include "server/server_config.h"
#include "server/session_table.h"
#include "transport/mux/frame.h"
#include "transport/session/transport_session.h"
#include "transport/udp_socket/udp_socket.h"
#include "tun/routing.h"
#include "tun/tun_device.h"

using namespace veil;

namespace {
constexpr std::size_t kMaxPacketSize = 65535;

bool load_key_from_file(const std::string& path, std::array<std::uint8_t, 32>& key,
                        std::error_code& ec) {
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    ec = std::error_code(errno, std::generic_category());
    return false;
  }
  file.read(reinterpret_cast<char*>(key.data()), static_cast<std::streamsize>(key.size()));
  return file.gcount() == static_cast<std::streamsize>(key.size());
}

// Helper functions to avoid LOG_* macros in lambdas (clang-tidy bugprone-lambda-function-name).
void log_signal_sigint() {
  LOG_INFO("Received SIGINT, shutting down...");
}

void log_signal_sigterm() {
  LOG_INFO("Received SIGTERM, shutting down...");
}

void log_tun_write_error(const std::error_code& ec) {
  LOG_ERROR("Failed to write to TUN: {}", ec.message());
}

void log_handshake_send_error(const std::error_code& ec) {
  LOG_ERROR("Failed to send handshake response: {}", ec.message());
}

void log_new_client(const std::string& host, std::uint16_t port, std::uint64_t session_id) {
  LOG_INFO("New client connected from {}:{}, session {}", host, port, session_id);
}

void log_packet_received([[maybe_unused]] std::size_t size,
                         [[maybe_unused]] const std::string& host,
                         [[maybe_unused]] std::uint16_t port) {
  LOG_DEBUG("Received {} bytes from {}:{}", size, host, port);
}
}  // namespace

int main(int argc, char* argv[]) {
  // Parse configuration.
  server::ServerConfig config;
  std::error_code ec;

  if (!server::parse_args(argc, argv, config, ec)) {
    std::cerr << "Failed to parse arguments: " << ec.message() << '\n';
    return EXIT_FAILURE;
  }

  // Validate configuration.
  std::string validation_error;
  if (!server::validate_config(config, validation_error)) {
    std::cerr << "Configuration error: " << validation_error << '\n';
    return EXIT_FAILURE;
  }

  // Initialize logging.
  logging::configure_logging(config.verbose ? logging::LogLevel::debug : logging::LogLevel::info, true);
  LOG_INFO("VEIL Server starting...");

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

  // Create PID file if not daemonizing.
  std::unique_ptr<daemon::PidFile> pid_file;
  if (!config.daemon_mode && !config.pid_file.empty()) {
    pid_file = std::make_unique<daemon::PidFile>(config.pid_file);
    if (!pid_file->create(ec)) {
      LOG_WARN("Failed to create PID file: {}", ec.message());
    }
  }

  // Load keys.
  [[maybe_unused]] crypto::KeyPair key_pair = crypto::generate_x25519_keypair();
  std::vector<std::uint8_t> psk;
  if (!config.tunnel.key_file.empty()) {
    std::array<std::uint8_t, 32> psk_arr{};
    if (load_key_from_file(config.tunnel.key_file, psk_arr, ec)) {
      psk.assign(psk_arr.begin(), psk_arr.end());
    } else {
      LOG_WARN("Failed to load key file: {}", ec.message());
    }
  }

  // Open TUN device.
  tun::TunDevice tun_device;
  if (!tun_device.open(config.tunnel.tun, ec)) {
    LOG_ERROR("Failed to open TUN device: {}", ec.message());
    return EXIT_FAILURE;
  }
  LOG_INFO("TUN device {} opened with IP {}", tun_device.device_name(), config.tunnel.tun.ip_address);

  // Setup routing and NAT.
  tun::RouteManager route_manager;

  if (config.nat.enable_forwarding) {
    config.nat.internal_interface = tun_device.device_name();
    if (!route_manager.configure_nat(config.nat, ec)) {
      LOG_ERROR("Failed to configure NAT: {}", ec.message());
      return EXIT_FAILURE;
    }
    LOG_INFO("NAT configured: {} -> {}", config.nat.internal_interface, config.nat.external_interface);
  }

  // Open UDP socket.
  transport::UdpSocket udp_socket;
  if (!udp_socket.open(config.listen_port, true, ec)) {
    LOG_ERROR("Failed to open UDP socket: {}", ec.message());
    return EXIT_FAILURE;
  }
  LOG_INFO("Listening on {}:{}", config.listen_address, config.listen_port);

  // Create session table.
  server::SessionTable session_table(config.max_clients, config.session_timeout, config.ip_pool_start,
                                      config.ip_pool_end);

  // Create handshake responder.
  utils::TokenBucket rate_limiter(100.0, std::chrono::milliseconds(10));  // 100 tokens, 10ms refill
  handshake::HandshakeResponder responder(psk, config.tunnel.handshake_skew_tolerance, rate_limiter);

  // Setup signal handlers.
  auto& sig_handler = signal::SignalHandler::instance();
  sig_handler.setup_defaults();

  std::atomic<bool> running{true};
  sig_handler.on(signal::Signal::kInterrupt, [&running](signal::Signal) {
    log_signal_sigint();
    running.store(false);
  });
  sig_handler.on(signal::Signal::kTerminate, [&running](signal::Signal) {
    log_signal_sigterm();
    running.store(false);
  });

  // Session cleanup timer.
  auto last_cleanup = std::chrono::steady_clock::now();

  // Main server loop.
  LOG_INFO("Server running, accepting connections...");
  std::array<std::uint8_t, kMaxPacketSize> buffer{};

  while (running.load() && !sig_handler.should_terminate()) {
    // Poll UDP socket.
    udp_socket.poll(
        [&](const transport::UdpPacket& pkt) {
          log_packet_received(pkt.data.size(), pkt.remote.host, pkt.remote.port);

          // Check if this is from an existing session.
          auto* session = session_table.find_by_endpoint(pkt.remote);

          if (session != nullptr) {
            // Process data from existing session.
            session_table.update_activity(session->session_id);
            session->packets_received++;
            session->bytes_received += pkt.data.size();

            if (session->transport) {
              auto frames = session->transport->decrypt_packet(pkt.data);
              if (frames) {
                for (const auto& frame : *frames) {
                  if (frame.kind == mux::FrameKind::kData) {
                    // Write to TUN device.
                    if (!tun_device.write(frame.data.payload, ec)) {
                      log_tun_write_error(ec);
                    }
                  } else if (frame.kind == mux::FrameKind::kAck) {
                    session->transport->process_ack(frame.ack);
                  }
                }
              }
            }
          } else {
            // New connection - handle handshake.
            auto hs_result = responder.handle_init(pkt.data);
            if (hs_result) {
              if (!udp_socket.send(hs_result->response, pkt.remote, ec)) {
                log_handshake_send_error(ec);
              } else {
                // Create transport session.
                auto transport = std::make_unique<transport::TransportSession>(
                    hs_result->session, config.tunnel.transport);

                // Create client session.
                auto session_id = session_table.create_session(pkt.remote, std::move(transport));
                if (session_id) {
                  log_new_client(pkt.remote.host, pkt.remote.port, *session_id);
                }
              }
            }
          }
        },
        10, ec);

    // Read from TUN and route to appropriate client.
    auto tun_read = tun_device.read_into(buffer, ec);
    if (tun_read > 0) {
      // Parse IP header to find destination.
      if (tun_read >= 20) {
        // Extract destination IP from IPv4 header (bytes 16-19).
        std::uint32_t dst_ip = (static_cast<std::uint32_t>(buffer[16]) << 24) |
                               (static_cast<std::uint32_t>(buffer[17]) << 16) |
                               (static_cast<std::uint32_t>(buffer[18]) << 8) |
                               static_cast<std::uint32_t>(buffer[19]);

        // Convert to string.
        char ip_str[INET_ADDRSTRLEN];
        struct in_addr addr {};
        addr.s_addr = htonl(dst_ip);
        inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

        // Find session by tunnel IP.
        auto* session = session_table.find_by_tunnel_ip(ip_str);
        if (session != nullptr && session->transport) {
          // Encrypt and send.
          auto packets = session->transport->encrypt_data(
              std::span<const std::uint8_t>(buffer.data(), static_cast<std::size_t>(tun_read)));
          for (const auto& pkt : packets) {
            if (!udp_socket.send(pkt, session->endpoint, ec)) {
              LOG_ERROR("Failed to send to client: {}", ec.message());
            } else {
              session->packets_sent++;
              session->bytes_sent += pkt.size();
            }
          }
        }
      }
    }

    // Periodic session cleanup.
    auto now = std::chrono::steady_clock::now();
    if (now - last_cleanup >= config.cleanup_interval) {
      auto expired = session_table.cleanup_expired();
      if (expired > 0) {
        LOG_INFO("Cleaned up {} expired sessions", expired);
      }
      last_cleanup = now;
    }

    // Process retransmits for all sessions.
    for (auto* session : session_table.get_all_sessions()) {
      if (session->transport) {
        auto retransmits = session->transport->get_retransmit_packets();
        for (const auto& pkt : retransmits) {
          if (!udp_socket.send(pkt, session->endpoint, ec)) {
            LOG_WARN("Failed to retransmit to client: {}", ec.message());
          }
        }
      }
    }
  }

  // Cleanup.
  LOG_INFO("Shutting down...");
  route_manager.cleanup();

  LOG_INFO("VEIL Server stopped");
  return EXIT_SUCCESS;
}
