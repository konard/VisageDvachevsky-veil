#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "common/handshake/handshake_processor.h"
#include "transport/session/transport_session.h"
#include "transport/udp_socket/udp_socket.h"

namespace veil::server {

// Client session information.
struct ClientSession {
  // Unique session identifier.
  std::uint64_t session_id{0};

  // Client endpoint.
  transport::UdpEndpoint endpoint;

  // Assigned tunnel IP.
  std::string tunnel_ip;

  // Transport session.
  std::unique_ptr<transport::TransportSession> transport;

  // Timestamps.
  std::chrono::steady_clock::time_point connected_at;
  std::chrono::steady_clock::time_point last_activity;

  // Statistics.
  std::uint64_t bytes_received{0};
  std::uint64_t bytes_sent{0};
  std::uint64_t packets_received{0};
  std::uint64_t packets_sent{0};
};

// Session table statistics.
struct SessionTableStats {
  std::size_t active_sessions{0};
  std::size_t total_sessions_created{0};
  std::size_t sessions_timed_out{0};
  std::size_t sessions_rejected_full{0};
};

// Manages client sessions and IP address allocation.
class SessionTable {
 public:
  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;

  SessionTable(std::size_t max_clients, std::chrono::seconds session_timeout,
               const std::string& ip_pool_start, const std::string& ip_pool_end,
               std::function<TimePoint()> now_fn = Clock::now);

  // Create a new session for a client.
  // Returns session ID on success, nullopt if table is full.
  std::optional<std::uint64_t> create_session(const transport::UdpEndpoint& endpoint,
                                                std::unique_ptr<transport::TransportSession> transport);

  // Find session by session ID.
  ClientSession* find_by_id(std::uint64_t session_id);

  // Find session by client endpoint.
  ClientSession* find_by_endpoint(const transport::UdpEndpoint& endpoint);

  // Find session by tunnel IP.
  ClientSession* find_by_tunnel_ip(const std::string& ip);

  // Update last activity timestamp.
  void update_activity(std::uint64_t session_id);

  // Remove a session.
  bool remove_session(std::uint64_t session_id);

  // Remove sessions that have timed out.
  // Returns number of sessions removed.
  std::size_t cleanup_expired();

  // Get all active sessions.
  std::vector<ClientSession*> get_all_sessions();

  // Get statistics.
  const SessionTableStats& stats() const { return stats_; }

  // Get current session count.
  std::size_t session_count() const { return sessions_.size(); }

  // Check if table is full.
  bool is_full() const { return sessions_.size() >= max_clients_; }

 private:
  // Allocate an IP from the pool.
  std::optional<std::string> allocate_ip();

  // Release an IP back to the pool.
  void release_ip(const std::string& ip);

  // Generate unique session ID.
  std::uint64_t generate_session_id();

  // Parse IP address to uint32.
  static std::uint32_t ip_to_uint(const std::string& ip);

  // Convert uint32 to IP string.
  static std::string uint_to_ip(std::uint32_t ip);

  std::size_t max_clients_;
  std::chrono::seconds session_timeout_;
  std::function<TimePoint()> now_fn_;

  // IP pool range.
  std::uint32_t ip_pool_start_;
  std::uint32_t ip_pool_end_;

  // Sessions indexed by ID.
  std::unordered_map<std::uint64_t, std::unique_ptr<ClientSession>> sessions_;

  // Endpoint to session ID mapping.
  std::unordered_map<std::string, std::uint64_t> endpoint_index_;

  // Tunnel IP to session ID mapping.
  std::unordered_map<std::string, std::uint64_t> ip_index_;

  // Available IPs in the pool.
  std::vector<std::uint32_t> available_ips_;

  // Next session ID.
  std::uint64_t next_session_id_{1};

  // Statistics.
  SessionTableStats stats_;

  // Mutex for thread safety.
  mutable std::mutex mutex_;
};

}  // namespace veil::server
