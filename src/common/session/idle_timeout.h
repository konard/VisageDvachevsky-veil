#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>

namespace veil::session {

// Multi-level idle timeout state.
enum class IdleTimeoutLevel : std::uint8_t {
  kNone = 0,           // Not idle
  kWarning = 1,        // Warning threshold reached
  kSoftClose = 2,      // Soft close threshold reached
  kForcedClose = 3     // Forced close threshold reached
};

// Convert idle timeout level to string.
const char* idle_timeout_level_to_string(IdleTimeoutLevel level);

// Configuration for enhanced idle timeout.
struct IdleTimeoutConfig {
  // Warning threshold - sends notification.
  std::chrono::seconds warning_threshold{270};
  // Soft close threshold - initiates graceful close.
  std::chrono::seconds soft_close_threshold{300};
  // Forced close threshold - immediate termination.
  std::chrono::seconds forced_close_threshold{330};
  // Keep-alive probe interval.
  std::chrono::seconds keepalive_interval{30};
  // Number of missed probes before considering dead.
  std::uint32_t max_missed_probes{3};
  // Enable keep-alive probing.
  bool enable_keepalive{true};
};

// Activity types for tracking.
enum class ActivityType : std::uint8_t {
  kReceive = 0,       // Data received
  kTransmit = 1,      // Data sent
  kHeartbeat = 2,     // Heartbeat received
  kKeepalive = 3,     // Keep-alive response received
  kAny = 4            // Any activity
};

// Callbacks for idle timeout events.
struct IdleTimeoutCallbacks {
  // Called when warning threshold reached.
  std::function<void()> on_warning;
  // Called when soft close threshold reached.
  std::function<void()> on_soft_close;
  // Called when forced close threshold reached.
  std::function<void()> on_forced_close;
  // Called when keep-alive probe should be sent.
  std::function<void()> on_send_keepalive;
  // Called when connection is considered dead (missed probes).
  std::function<void()> on_connection_dead;
};

// Enhanced idle timeout tracker.
class IdleTimeout {
 public:
  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;

  explicit IdleTimeout(IdleTimeoutConfig config = {},
                       IdleTimeoutCallbacks callbacks = {},
                       std::function<TimePoint()> now_fn = Clock::now);

  // Record activity (resets idle timer).
  void record_activity(ActivityType type = ActivityType::kAny);

  // Record received data.
  void record_rx() { record_activity(ActivityType::kReceive); }

  // Record transmitted data.
  void record_tx() { record_activity(ActivityType::kTransmit); }

  // Record heartbeat received.
  void record_heartbeat() { record_activity(ActivityType::kHeartbeat); }

  // Record keep-alive response.
  void record_keepalive_response();

  // Record that a keep-alive probe was sent.
  void record_keepalive_sent();

  // Check timeouts and trigger callbacks.
  // Call this periodically. Returns current idle level.
  IdleTimeoutLevel check();

  // Get current idle timeout level without triggering callbacks.
  IdleTimeoutLevel current_level() const;

  // Check if keep-alive probe should be sent.
  bool should_send_keepalive() const;

  // Check if connection is considered dead (missed probes).
  bool is_connection_dead() const;

  // Get current idle duration.
  std::chrono::seconds idle_duration() const;

  // Get time until next timeout level.
  std::chrono::seconds time_until_next_level() const;

  // Get number of missed keep-alive probes.
  std::uint32_t missed_probes() const { return missed_probes_; }

  // Reset all timers and state.
  void reset();

  // Get last activity timestamps.
  TimePoint last_rx() const { return last_rx_; }
  TimePoint last_tx() const { return last_tx_; }
  TimePoint last_heartbeat() const { return last_heartbeat_; }
  TimePoint last_activity() const { return last_activity_; }

  // Get configuration.
  const IdleTimeoutConfig& config() const { return config_; }

 private:
  void check_keepalive();

  IdleTimeoutConfig config_;
  IdleTimeoutCallbacks callbacks_;
  std::function<TimePoint()> now_fn_;

  TimePoint last_rx_;
  TimePoint last_tx_;
  TimePoint last_heartbeat_;
  TimePoint last_activity_;
  TimePoint last_keepalive_sent_;
  TimePoint last_keepalive_response_;

  IdleTimeoutLevel current_level_{IdleTimeoutLevel::kNone};
  std::uint32_t missed_probes_{0};
  bool warning_triggered_{false};
  bool soft_close_triggered_{false};
};

// Keep-alive probe manager for multiple sessions.
class KeepaliveManager {
 public:
  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;
  using SessionId = std::uint64_t;

  // Callback to send keep-alive probe to a session.
  using SendProbeCallback = std::function<void(SessionId)>;

  explicit KeepaliveManager(std::chrono::seconds probe_interval = std::chrono::seconds(30),
                            std::function<TimePoint()> now_fn = Clock::now);

  // Register a session for keep-alive tracking.
  void register_session(SessionId session_id, IdleTimeout* timeout);

  // Unregister a session.
  void unregister_session(SessionId session_id);

  // Set callback for sending probes.
  void set_send_probe_callback(SendProbeCallback callback);

  // Check all sessions and send probes as needed.
  // Returns number of probes sent.
  std::size_t check_and_send_probes();

  // Get sessions that are considered dead.
  std::vector<SessionId> get_dead_sessions() const;

  // Get number of tracked sessions.
  std::size_t session_count() const { return sessions_.size(); }

 private:
  std::chrono::seconds probe_interval_;
  std::function<TimePoint()> now_fn_;
  SendProbeCallback send_probe_callback_;
  std::unordered_map<SessionId, IdleTimeout*> sessions_;
  TimePoint last_check_;
};

}  // namespace veil::session
