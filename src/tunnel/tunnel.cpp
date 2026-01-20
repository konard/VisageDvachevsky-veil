#include "tunnel/tunnel.h"

#include <array>
#include <fstream>

#include "common/handshake/handshake_processor.h"
#include "common/logging/logger.h"
#include "common/signal/signal_handler.h"
#include "common/utils/rate_limiter.h"

namespace veil::tunnel {

namespace {
constexpr std::size_t kMaxPacketSize = 65535;

bool load_key_from_file(const std::string& path, std::vector<std::uint8_t>& key,
                        std::error_code& ec) {
  std::ifstream file(path, std::ios::binary);
  if (!file) {
    ec = std::error_code(errno, std::generic_category());
    return false;
  }

  key.resize(32);
  file.read(reinterpret_cast<char*>(key.data()), static_cast<std::streamsize>(key.size()));
  if (file.gcount() != static_cast<std::streamsize>(key.size())) {
    ec = std::make_error_code(std::errc::io_error);
    return false;
  }

  return true;
}
}  // namespace

Tunnel::Tunnel(TunnelConfig config, std::function<TimePoint()> now_fn)
    : config_(std::move(config)), now_fn_(std::move(now_fn)), pmtu_discovery_(config_.pmtu, now_fn_) {}

Tunnel::~Tunnel() { stop(); }

bool Tunnel::initialize(std::error_code& ec) {
  LOG_INFO("Initializing tunnel...");

  // Load pre-shared key if specified.
  if (!config_.key_file.empty()) {
    if (!load_key_from_file(config_.key_file, config_.psk, ec)) {
      LOG_ERROR("Failed to load key file {}: {}", config_.key_file, ec.message());
      return false;
    }
    LOG_DEBUG("Loaded pre-shared key from {}", config_.key_file);
  }

  // Generate ephemeral key pair for this session.
  key_pair_ = crypto::generate_x25519_keypair();
  LOG_DEBUG("Generated ephemeral key pair");

  // Load obfuscation seed if specified.
  if (!config_.obfuscation_seed_file.empty()) {
    std::vector<std::uint8_t> seed;
    if (!load_key_from_file(config_.obfuscation_seed_file, seed, ec)) {
      LOG_WARN("Failed to load obfuscation seed: {}", ec.message());
      // Continue without obfuscation seed.
    } else if (seed.size() >= obfuscation::kProfileSeedSize) {
      std::copy_n(seed.begin(), obfuscation::kProfileSeedSize,
                  obfuscation_profile_.profile_seed.begin());
      obfuscation_profile_.enabled = true;
      LOG_DEBUG("Loaded obfuscation seed");
    }
  }

  // Open TUN device.
  if (!tun_device_.open(config_.tun, ec)) {
    LOG_ERROR("Failed to open TUN device: {}", ec.message());
    return false;
  }
  LOG_INFO("TUN device {} opened with IP {}", tun_device_.device_name(), config_.tun.ip_address);

  // Open UDP socket.
  if (!udp_socket_.open(config_.local_port, true, ec)) {
    LOG_ERROR("Failed to open UDP socket: {}", ec.message());
    return false;
  }
  LOG_INFO("UDP socket opened on port {}", config_.local_port);

  // Create event loop.
  event_loop_ = std::make_unique<transport::EventLoop>(config_.event_loop, now_fn_);

  // Setup PMTU change callback.
  pmtu_discovery_.set_mtu_change_callback(
      [this](const std::string& peer, int old_mtu, int new_mtu) {
        handle_mtu_change(peer, old_mtu, new_mtu);
      });

  set_state(ConnectionState::kDisconnected);
  LOG_INFO("Tunnel initialized successfully");
  return true;
}

void Tunnel::run() {
  if (running_.load()) {
    return;
  }

  running_.store(true);
  LOG_INFO("Tunnel starting...");

  // Setup signal handlers.
  auto& sig_handler = signal::SignalHandler::instance();
  sig_handler.setup_defaults();

  // Connect to server (for client mode).
  if (!config_.server_address.empty()) {
    set_state(ConnectionState::kConnecting);

    std::error_code ec;
    transport::UdpEndpoint remote{config_.server_address, config_.server_port};
    if (!udp_socket_.connect(remote, ec)) {
      LOG_ERROR("Failed to connect to server: {}", ec.message());
      if (error_callback_) {
        error_callback_("Failed to connect: " + ec.message());
      }
      set_state(ConnectionState::kDisconnected);
      running_.store(false);
      return;
    }

    // Perform handshake.
    set_state(ConnectionState::kHandshaking);
    if (!perform_handshake(ec)) {
      LOG_ERROR("Handshake failed: {}", ec.message());
      if (error_callback_) {
        error_callback_("Handshake failed: " + ec.message());
      }
      handle_reconnect();
    } else {
      set_state(ConnectionState::kConnected);
      stats_.connected_since = now_fn_();
    }
  }

  // Main event loop.
  std::array<std::uint8_t, kMaxPacketSize> tun_buffer{};

  while (running_.load() && !sig_handler.should_terminate()) {
    std::error_code ec;

    // Check TUN device for incoming packets.
    auto tun_read = tun_device_.read_into(tun_buffer, ec);
    if (tun_read > 0) {
      on_tun_packet(std::span<const std::uint8_t>(tun_buffer.data(), static_cast<std::size_t>(tun_read)));
    } else if (tun_read < 0) {
      LOG_ERROR("TUN read error: {}", ec.message());
      stats_.tun_read_errors++;
    }

    // Poll UDP socket for incoming packets.
    udp_socket_.poll(
        [this](const transport::UdpPacket& pkt) {
          on_udp_packet(pkt.data, pkt.remote);
        },
        10, ec);

    // Process session timers if we have an active session.
    if (session_) {
      // Check for retransmits.
      auto retransmits = session_->get_retransmit_packets();
      for (const auto& pkt : retransmits) {
        std::error_code send_ec;
        transport::UdpEndpoint remote{config_.server_address, config_.server_port};
        if (!udp_socket_.send(pkt, remote, send_ec)) {
          LOG_WARN("Failed to send retransmit: {}", send_ec.message());
        }
      }

      // Check for session rotation.
      if (session_->should_rotate_session()) {
        session_->rotate_session();
        LOG_DEBUG("Session rotated");
      }
    }

    // Handle reconnection if needed.
    if (state_.load() == ConnectionState::kReconnecting) {
      handle_reconnect();
    }

    stats_.last_activity = now_fn_();
  }

  LOG_INFO("Tunnel stopping...");
  set_state(ConnectionState::kDisconnected);
  running_.store(false);
}

void Tunnel::stop() {
  running_.store(false);
  if (event_loop_) {
    event_loop_->stop();
  }
  LOG_INFO("Tunnel stopped");
}

void Tunnel::on_tun_packet(std::span<const std::uint8_t> packet) {
  stats_.tun_packets_received++;
  stats_.tun_bytes_received += packet.size();

  if (!session_ || state_.load() != ConnectionState::kConnected) {
    return;
  }

  // Encrypt and send through UDP.
  auto encrypted_packets = session_->encrypt_data(packet);
  for (const auto& enc_pkt : encrypted_packets) {
    std::error_code ec;
    transport::UdpEndpoint remote{config_.server_address, config_.server_port};
    if (!udp_socket_.send(enc_pkt, remote, ec)) {
      LOG_WARN("Failed to send encrypted packet: {}", ec.message());
      stats_.encrypt_errors++;
      continue;
    }
    stats_.udp_packets_sent++;
    stats_.udp_bytes_sent += enc_pkt.size();
  }
}

void Tunnel::on_udp_packet(std::span<const std::uint8_t> packet,
                            const transport::UdpEndpoint& remote) {
  stats_.udp_packets_received++;
  stats_.udp_bytes_received += packet.size();

  if (!session_) {
    return;
  }

  // Decrypt the packet.
  auto frames = session_->decrypt_packet(packet);
  if (!frames) {
    LOG_DEBUG("Failed to decrypt packet from {}:{}", remote.host, remote.port);
    stats_.decrypt_errors++;
    return;
  }

  // Process each frame.
  for (const auto& frame : *frames) {
    if (frame.kind == mux::FrameKind::kData) {
      // Write decrypted data to TUN device.
      std::error_code ec;
      if (!tun_device_.write(frame.data.payload, ec)) {
        LOG_ERROR("Failed to write to TUN: {}", ec.message());
        stats_.tun_write_errors++;
        continue;
      }
      stats_.tun_packets_sent++;
      stats_.tun_bytes_sent += frame.data.payload.size();
    } else if (frame.kind == mux::FrameKind::kAck) {
      session_->process_ack(frame.ack);
    }
  }

  // Update PMTU discovery.
  pmtu_discovery_.handle_probe_success(remote.host, static_cast<int>(packet.size()));
}

bool Tunnel::perform_handshake(std::error_code& ec) {
  LOG_INFO("Performing handshake with {}:{}", config_.server_address, config_.server_port);

  // Create handshake initiator.
  handshake::HandshakeInitiator initiator(config_.psk, config_.handshake_skew_tolerance);

  // Generate INIT message.
  auto init_msg = initiator.create_init();
  if (init_msg.empty()) {
    ec = std::make_error_code(std::errc::protocol_error);
    LOG_ERROR("Failed to create handshake INIT message");
    return false;
  }

  // Send INIT message.
  transport::UdpEndpoint remote{config_.server_address, config_.server_port};
  if (!udp_socket_.send(init_msg, remote, ec)) {
    LOG_ERROR("Failed to send handshake INIT: {}", ec.message());
    return false;
  }
  LOG_DEBUG("Sent handshake INIT ({} bytes)", init_msg.size());

  // Wait for RESPONSE.
  std::vector<std::uint8_t> response;
  bool received = false;

  udp_socket_.poll(
      [&response, &received](const transport::UdpPacket& pkt) {
        response = pkt.data;
        received = true;
      },
      static_cast<int>(config_.handshake_skew_tolerance.count()), ec);

  if (!received || response.empty()) {
    ec = std::make_error_code(std::errc::timed_out);
    LOG_ERROR("Handshake timeout waiting for RESPONSE");
    return false;
  }

  // Process RESPONSE.
  auto hs_session = initiator.consume_response(response);
  if (!hs_session) {
    ec = std::make_error_code(std::errc::protocol_error);
    LOG_ERROR("Failed to process handshake RESPONSE");
    return false;
  }

  // Create transport session from handshake result.
  session_ = std::make_unique<transport::TransportSession>(*hs_session, config_.transport, now_fn_);

  LOG_INFO("Handshake completed successfully, session ID: {}", session_->session_id());
  return true;
}

void Tunnel::set_state(ConnectionState new_state) {
  ConnectionState old_state = state_.exchange(new_state);
  if (old_state != new_state) {
    LOG_INFO("Connection state: {} -> {}",
             static_cast<int>(old_state), static_cast<int>(new_state));
    if (state_change_callback_) {
      state_change_callback_(old_state, new_state);
    }
  }
}

bool Tunnel::send_packet(std::span<const std::uint8_t> data) {
  if (!session_ || state_.load() != ConnectionState::kConnected) {
    return false;
  }

  auto encrypted_packets = session_->encrypt_data(data);
  for (const auto& pkt : encrypted_packets) {
    std::error_code ec;
    transport::UdpEndpoint remote{config_.server_address, config_.server_port};
    if (!udp_socket_.send(pkt, remote, ec)) {
      return false;
    }
  }
  return true;
}

void Tunnel::handle_reconnect() {
  if (!config_.auto_reconnect) {
    set_state(ConnectionState::kDisconnected);
    return;
  }

  // Check if we've exceeded max attempts.
  if (config_.max_reconnect_attempts > 0 && reconnect_attempts_ >= config_.max_reconnect_attempts) {
    LOG_ERROR("Max reconnection attempts ({}) exceeded", config_.max_reconnect_attempts);
    set_state(ConnectionState::kDisconnected);
    if (error_callback_) {
      error_callback_("Max reconnection attempts exceeded");
    }
    return;
  }

  // Check if enough time has passed since last attempt.
  auto now = now_fn_();
  auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_reconnect_attempt_);
  if (elapsed < config_.reconnect_delay) {
    return;
  }

  reconnect_attempts_++;
  last_reconnect_attempt_ = now;
  LOG_INFO("Reconnection attempt {} (delay: {}ms)", reconnect_attempts_,
           config_.reconnect_delay.count());

  set_state(ConnectionState::kConnecting);

  // Re-initialize socket.
  udp_socket_.close();
  std::error_code ec;
  if (!udp_socket_.open(config_.local_port, true, ec)) {
    LOG_ERROR("Failed to reopen UDP socket: {}", ec.message());
    set_state(ConnectionState::kReconnecting);
    return;
  }

  // Reconnect.
  transport::UdpEndpoint remote{config_.server_address, config_.server_port};
  if (!udp_socket_.connect(remote, ec)) {
    LOG_ERROR("Failed to reconnect: {}", ec.message());
    set_state(ConnectionState::kReconnecting);
    return;
  }

  // Perform handshake.
  set_state(ConnectionState::kHandshaking);
  if (!perform_handshake(ec)) {
    LOG_ERROR("Reconnection handshake failed: {}", ec.message());
    set_state(ConnectionState::kReconnecting);
    return;
  }

  // Success!
  reconnect_attempts_ = 0;
  stats_.reconnect_count++;
  stats_.connected_since = now_fn_();
  set_state(ConnectionState::kConnected);
  LOG_INFO("Reconnected successfully");
}

void Tunnel::on_state_change(StateChangeCallback callback) {
  state_change_callback_ = std::move(callback);
}

void Tunnel::on_error(ErrorCallback callback) { error_callback_ = std::move(callback); }

void Tunnel::handle_mtu_change(const std::string& peer, int old_mtu, int new_mtu) {
  LOG_INFO("MTU changed for {}: {} -> {}", peer, old_mtu, new_mtu);
  // Update TUN device MTU.
  std::error_code mtu_ec;
  if (!tun_device_.set_mtu(new_mtu, mtu_ec)) {
    LOG_WARN("Failed to update TUN MTU: {}", mtu_ec.message());
  }
}

}  // namespace veil::tunnel
