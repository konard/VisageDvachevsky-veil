#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <system_error>
#include <vector>

#include "common/crypto/crypto_engine.h"
#include "common/obfuscation/obfuscation_profile.h"
#include "transport/event_loop/event_loop.h"
#include "transport/mux/frame.h"
#include "transport/session/transport_session.h"
#include "transport/udp_socket/udp_socket.h"
#include "tun/mtu_discovery.h"
#include "tun/routing.h"
#include "tun/tun_device.h"

namespace veil::tunnel {

// Connection state.
enum class ConnectionState {
  kDisconnected,
  kConnecting,
  kHandshaking,
  kConnected,
  kReconnecting,
};

// Tunnel statistics.
struct TunnelStats {
  // Packet counts.
  std::uint64_t tun_packets_received{0};
  std::uint64_t tun_packets_sent{0};
  std::uint64_t udp_packets_received{0};
  std::uint64_t udp_packets_sent{0};

  // Byte counts.
  std::uint64_t tun_bytes_received{0};
  std::uint64_t tun_bytes_sent{0};
  std::uint64_t udp_bytes_received{0};
  std::uint64_t udp_bytes_sent{0};

  // Errors.
  std::uint64_t decrypt_errors{0};
  std::uint64_t encrypt_errors{0};
  std::uint64_t tun_read_errors{0};
  std::uint64_t tun_write_errors{0};

  // Connection.
  std::uint64_t reconnect_count{0};
  std::chrono::steady_clock::time_point connected_since;
  std::chrono::steady_clock::time_point last_activity;
};

// Configuration for the tunnel.
struct TunnelConfig {
  // TUN device configuration.
  tun::TunConfig tun;

  // Remote server address (for client mode).
  std::string server_address;
  std::uint16_t server_port{4433};

  // Local bind port (for server mode, 0 for client).
  std::uint16_t local_port{0};

  // Pre-shared key file path.
  std::string key_file;

  // Obfuscation seed file path.
  std::string obfuscation_seed_file;

  // Transport session configuration.
  transport::TransportSessionConfig transport;

  // Event loop configuration.
  transport::EventLoopConfig event_loop;

  // PMTU discovery configuration.
  tun::PmtuConfig pmtu;

  // Reconnection settings.
  bool auto_reconnect{true};
  std::chrono::milliseconds reconnect_delay{5000};
  int max_reconnect_attempts{0};  // 0 = unlimited.

  // Logging.
  bool verbose{false};

  // Pre-shared key (loaded from file).
  std::vector<std::uint8_t> psk;

  // Timestamp skew tolerance for handshake.
  std::chrono::milliseconds handshake_skew_tolerance{30000};
};

// Callback types.
using StateChangeCallback = std::function<void(ConnectionState old_state, ConnectionState new_state)>;
using ErrorCallback = std::function<void(const std::string& error)>;

// Main tunnel class that bridges TUN device with encrypted UDP transport.
class Tunnel {
 public:
  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;

  explicit Tunnel(TunnelConfig config, std::function<TimePoint()> now_fn = Clock::now);
  virtual ~Tunnel();

  // Non-copyable, non-movable.
  Tunnel(const Tunnel&) = delete;
  Tunnel& operator=(const Tunnel&) = delete;
  Tunnel(Tunnel&&) = delete;
  Tunnel& operator=(Tunnel&&) = delete;

  // Initialize the tunnel (creates TUN device, loads keys).
  bool initialize(std::error_code& ec);

  // Start the tunnel (begins event loop).
  // This is blocking; call stop() from another thread or signal handler.
  void run();

  // Stop the tunnel gracefully.
  void stop();

  // Check if tunnel is running.
  bool is_running() const { return running_.load(); }

  // Get current connection state.
  ConnectionState state() const { return state_.load(); }

  // Get tunnel statistics.
  const TunnelStats& stats() const { return stats_; }

  // Set state change callback.
  void on_state_change(StateChangeCallback callback);

  // Set error callback.
  void on_error(ErrorCallback callback);

  // Get the TUN device.
  tun::TunDevice* tun_device() { return &tun_device_; }

  // Get the route manager.
  tun::RouteManager* route_manager() { return &route_manager_; }

 protected:
  // Called when a packet is received from the TUN device.
  virtual void on_tun_packet(std::span<const std::uint8_t> packet);

  // Called when a packet is received from the UDP socket.
  virtual void on_udp_packet(std::span<const std::uint8_t> packet, const transport::UdpEndpoint& remote);

  // Called to perform handshake (client initiates, server responds).
  virtual bool perform_handshake(std::error_code& ec);

  // Set connection state.
  void set_state(ConnectionState new_state);

  // Send packet through the tunnel.
  bool send_packet(std::span<const std::uint8_t> data);

  // Handle reconnection logic.
  void handle_reconnect();

  // Handle MTU change callback (moved out of lambda for clang-tidy).
  void handle_mtu_change(const std::string& peer, int old_mtu, int new_mtu);

  TunnelConfig config_;
  std::function<TimePoint()> now_fn_;

  // Components.
  tun::TunDevice tun_device_;
  tun::RouteManager route_manager_;
  tun::PmtuDiscovery pmtu_discovery_;
  transport::UdpSocket udp_socket_;
  std::unique_ptr<transport::TransportSession> session_;
  std::unique_ptr<transport::EventLoop> event_loop_;

  // Crypto.
  crypto::KeyPair key_pair_;
  obfuscation::ObfuscationProfile obfuscation_profile_;

  // State.
  std::atomic<bool> running_{false};
  std::atomic<ConnectionState> state_{ConnectionState::kDisconnected};

  // Statistics.
  TunnelStats stats_;

  // Callbacks.
  StateChangeCallback state_change_callback_;
  ErrorCallback error_callback_;

  // Reconnection.
  int reconnect_attempts_{0};
  TimePoint last_reconnect_attempt_;
};

}  // namespace veil::tunnel
