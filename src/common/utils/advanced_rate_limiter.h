#pragma once

#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <memory>


namespace veil::utils {

// Traffic priority levels for traffic shaping.
enum class TrafficPriority : std::uint8_t {
  kLow = 0,      // Background traffic, can be dropped first
  kNormal = 1,   // Regular data traffic
  kHigh = 2,     // Important traffic (e.g., control messages)
  kCritical = 3  // Must not be dropped (e.g., session keepalives)
};

// Configuration for the advanced rate limiter.
struct RateLimiterConfig {
  // Bandwidth limits in bytes per second.
  std::uint64_t bandwidth_bytes_per_sec{static_cast<std::uint64_t>(100) * 1024 * 1024};  // 100 MB/s default
  // Packets per second limit.
  std::uint64_t packets_per_sec{10000};
  // Burst allowance factor (1.0 = no burst, 2.0 = allow 2x burst).
  double burst_allowance_factor{1.5};
  // Penalty duration after burst exhaustion.
  std::chrono::milliseconds burst_penalty_duration{1000};
  // Maximum reconnections per minute for anti-abuse.
  std::uint32_t max_reconnects_per_minute{5};
  // Window size for tracking violations.
  std::chrono::seconds violation_tracking_window{60};
  // Traffic shaping: enable priority queuing.
  bool enable_traffic_shaping{true};
};

// Statistics tracked per client.
struct ClientRateLimitStats {
  std::uint64_t bytes_allowed{0};
  std::uint64_t bytes_denied{0};
  std::uint64_t packets_allowed{0};
  std::uint64_t packets_denied{0};
  std::uint64_t violations{0};
  std::uint64_t reconnects{0};
  std::chrono::steady_clock::time_point last_activity;
  std::chrono::steady_clock::time_point last_violation;
};

// Token bucket with burst support.
class BurstTokenBucket {
 public:
  using Clock = std::chrono::steady_clock;

  BurstTokenBucket(std::uint64_t rate_per_sec, double burst_factor,
                   std::chrono::milliseconds penalty_duration,
                   std::function<Clock::time_point()> now_fn = Clock::now);

  // Try to consume tokens. Returns true if allowed.
  bool try_consume(std::uint64_t tokens);

  // Check if currently in penalty period.
  bool is_penalized() const;

  // Get current token count.
  double current_tokens() const { return tokens_; }

  // Get burst capacity.
  double burst_capacity() const { return burst_capacity_; }

  // Reset the bucket.
  void reset();

 private:
  void refill();

  std::uint64_t rate_per_sec_;
  double burst_capacity_;
  double tokens_;
  std::chrono::milliseconds penalty_duration_;
  std::function<Clock::time_point()> now_fn_;
  Clock::time_point last_refill_;
  Clock::time_point penalty_end_;
  bool in_penalty_{false};
};

// Per-client rate limiter state.
class ClientRateLimiter {
 public:
  using Clock = std::chrono::steady_clock;

  ClientRateLimiter(const RateLimiterConfig& config,
                    std::function<Clock::time_point()> now_fn = Clock::now);

  // Check if a packet of given size and priority can be sent.
  // Returns true if allowed, false if should be dropped/delayed.
  bool allow_packet(std::uint64_t size_bytes, TrafficPriority priority = TrafficPriority::kNormal);

  // Record a reconnection attempt.
  // Returns true if allowed, false if abuse detected.
  bool record_reconnect();

  // Get current statistics.
  const ClientRateLimitStats& stats() const { return stats_; }

  // Check if client should be blocked due to violations.
  bool is_blocked() const;

  // Get remaining bandwidth budget for current window.
  std::uint64_t remaining_bandwidth() const;

  // Get remaining packet budget for current window.
  std::uint64_t remaining_packets() const;

 private:
  void cleanup_reconnect_history();

  RateLimiterConfig config_;
  std::function<Clock::time_point()> now_fn_;
  BurstTokenBucket bandwidth_bucket_;
  BurstTokenBucket packet_bucket_;
  std::deque<Clock::time_point> reconnect_history_;
  ClientRateLimitStats stats_;
};

// Advanced rate limiter managing multiple clients.
class AdvancedRateLimiter {
 public:
  using Clock = std::chrono::steady_clock;
  using ClientId = std::string;

  explicit AdvancedRateLimiter(RateLimiterConfig config = {},
                               std::function<Clock::time_point()> now_fn = Clock::now);

  // Set per-client configuration override.
  void set_client_config(const ClientId& client_id, const RateLimiterConfig& config);

  // Check if a packet can be sent for a client.
  bool allow_packet(const ClientId& client_id, std::uint64_t size_bytes,
                    TrafficPriority priority = TrafficPriority::kNormal);

  // Record a reconnection for a client.
  bool record_reconnect(const ClientId& client_id);

  // Remove a client from tracking.
  void remove_client(const ClientId& client_id);

  // Get stats for a specific client.
  std::optional<ClientRateLimitStats> get_client_stats(const ClientId& client_id) const;

  // Get global statistics across all clients.
  struct GlobalStats {
    std::size_t tracked_clients{0};
    std::uint64_t total_bytes_allowed{0};
    std::uint64_t total_bytes_denied{0};
    std::uint64_t total_packets_allowed{0};
    std::uint64_t total_packets_denied{0};
    std::uint64_t total_violations{0};
    std::size_t blocked_clients{0};
  };
  GlobalStats get_global_stats() const;

  // Clean up inactive clients (call periodically).
  std::size_t cleanup_inactive(std::chrono::seconds max_idle);

  // Get default config.
  const RateLimiterConfig& default_config() const { return default_config_; }

 private:
  ClientRateLimiter& get_or_create_client(const ClientId& client_id);

  RateLimiterConfig default_config_;
  std::function<Clock::time_point()> now_fn_;
  std::unordered_map<ClientId, std::unique_ptr<ClientRateLimiter>> clients_;
  std::unordered_map<ClientId, RateLimiterConfig> client_configs_;
};

}  // namespace veil::utils
