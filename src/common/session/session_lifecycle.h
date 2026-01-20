#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>
#include <memory>


namespace veil::session {

// Session state enum for lifecycle management.
enum class SessionState : std::uint8_t {
  kActive = 0,      // Normal operation
  kDraining = 1,    // Graceful shutdown in progress, processing pending packets
  kExpired = 2,     // Timeout reached, waiting for cleanup
  kTerminated = 3   // Forcefully terminated
};

// Convert session state to string.
const char* session_state_to_string(SessionState state);

// Configuration for session lifecycle.
struct SessionLifecycleConfig {
  // Idle timeout - no activity before warning.
  std::chrono::seconds idle_timeout{300};
  // Warning before idle timeout (sends notification).
  std::chrono::seconds idle_warning{270};
  // Absolute timeout - maximum session lifetime.
  std::chrono::seconds absolute_timeout{86400};  // 24 hours
  // Inactivity threshold - time without traffic considered inactive.
  std::chrono::seconds inactivity_threshold{60};
  // Maximum memory per session in bytes.
  std::size_t max_memory_per_session{static_cast<std::size_t>(10) * 1024 * 1024};  // 10 MB
  // Maximum packet queue size.
  std::size_t max_packet_queue{1000};
  // Drain timeout - how long to wait during graceful shutdown.
  std::chrono::seconds drain_timeout{5};
  // Cleanup interval for expired sessions.
  std::chrono::seconds cleanup_interval{60};
};

// Callbacks for session lifecycle events.
struct SessionLifecycleCallbacks {
  using SessionId = std::uint64_t;

  // Called when session is about to expire (idle warning).
  std::function<void(SessionId)> on_idle_warning;
  // Called when session transitions to draining state.
  std::function<void(SessionId)> on_draining;
  // Called when session is expired.
  std::function<void(SessionId)> on_expired;
  // Called when session is terminated.
  std::function<void(SessionId)> on_terminated;
  // Called when memory limit is exceeded.
  std::function<void(SessionId, std::size_t current, std::size_t limit)> on_memory_exceeded;
  // Called when packet queue is full.
  std::function<void(SessionId, std::size_t queue_size)> on_queue_full;
};

// Session lifecycle tracker for a single session.
class SessionLifecycle {
 public:
  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;
  using SessionId = std::uint64_t;

  SessionLifecycle(SessionId session_id, const SessionLifecycleConfig& config,
                   SessionLifecycleCallbacks callbacks = {},
                   std::function<TimePoint()> now_fn = Clock::now);

  // Get session ID.
  SessionId session_id() const { return session_id_; }

  // Get current state.
  SessionState state() const { return state_; }

  // Record activity (resets idle timer).
  void record_activity();

  // Record received data.
  void record_rx(std::size_t bytes);

  // Record transmitted data.
  void record_tx(std::size_t bytes);

  // Record memory usage change.
  void update_memory_usage(std::size_t bytes);

  // Record packet in queue.
  void record_queued_packet();

  // Record packet dequeued.
  void record_dequeued_packet();

  // Check and update session state based on timeouts.
  // Call this periodically. Returns true if state changed.
  bool check_timeouts();

  // Initiate graceful drain (transition to draining).
  void start_drain();

  // Force immediate termination.
  void terminate();

  // Check if session can accept new data.
  bool can_accept_data() const;

  // Check if session is still alive (not expired or terminated).
  bool is_alive() const;

  // Get time until idle timeout (0 if already timed out).
  std::chrono::seconds time_until_idle_timeout() const;

  // Get time until absolute timeout.
  std::chrono::seconds time_until_absolute_timeout() const;

  // Get session age.
  std::chrono::seconds age() const;

  // Statistics.
  struct Stats {
    std::uint64_t bytes_received{0};
    std::uint64_t bytes_sent{0};
    std::uint64_t packets_received{0};
    std::uint64_t packets_sent{0};
    std::size_t current_memory{0};
    std::size_t current_queue_size{0};
    std::size_t peak_memory{0};
    std::size_t peak_queue_size{0};
    TimePoint created_at;
    TimePoint last_rx;
    TimePoint last_tx;
    TimePoint last_activity;
  };
  const Stats& stats() const { return stats_; }

 private:
  void transition_to(SessionState new_state);

  SessionId session_id_;
  SessionLifecycleConfig config_;
  SessionLifecycleCallbacks callbacks_;
  std::function<TimePoint()> now_fn_;

  SessionState state_{SessionState::kActive};
  TimePoint created_at_;
  TimePoint drain_started_;
  Stats stats_;
};

// Manager for multiple session lifecycles.
class SessionLifecycleManager {
 public:
  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;
  using SessionId = std::uint64_t;

  explicit SessionLifecycleManager(SessionLifecycleConfig config = {},
                                    std::function<TimePoint()> now_fn = Clock::now);

  // Set default callbacks for new sessions.
  void set_default_callbacks(SessionLifecycleCallbacks callbacks);

  // Create a new session lifecycle tracker.
  SessionLifecycle& create_session(SessionId session_id);

  // Get existing session.
  SessionLifecycle* get_session(SessionId session_id);

  // Remove session from tracking.
  bool remove_session(SessionId session_id);

  // Check all sessions for timeouts.
  // Returns list of session IDs that changed state.
  std::vector<SessionId> check_all_timeouts();

  // Start draining all sessions (for graceful server shutdown).
  void drain_all();

  // Terminate all sessions immediately.
  void terminate_all();

  // Cleanup expired and terminated sessions.
  // Returns number of sessions removed.
  std::size_t cleanup();

  // Get number of sessions by state.
  struct SessionCounts {
    std::size_t active{0};
    std::size_t draining{0};
    std::size_t expired{0};
    std::size_t terminated{0};
    std::size_t total{0};
  };
  SessionCounts get_counts() const;

  // Get all session IDs in a specific state.
  std::vector<SessionId> get_sessions_in_state(SessionState state) const;

  // Get configuration.
  const SessionLifecycleConfig& config() const { return config_; }

 private:
  SessionLifecycleConfig config_;
  SessionLifecycleCallbacks default_callbacks_;
  std::function<TimePoint()> now_fn_;
  std::unordered_map<SessionId, std::unique_ptr<SessionLifecycle>> sessions_;
};

}  // namespace veil::session
