#pragma once

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace veil::utils {

// Degradation level indicating system load.
enum class DegradationLevel : std::uint8_t {
  kNormal = 0,     // Normal operation
  kLight = 1,      // Light degradation - reduce non-essential work
  kModerate = 2,   // Moderate degradation - reduce heartbeats, batch ACKs
  kSevere = 3,     // Severe degradation - minimal operations only
  kCritical = 4    // Critical - reject new connections
};

// Convert degradation level to string.
const char* degradation_level_to_string(DegradationLevel level);

// Configuration for graceful degradation.
struct DegradationConfig {
  // CPU threshold percentages for each level.
  double cpu_light_threshold{60.0};
  double cpu_moderate_threshold{75.0};
  double cpu_severe_threshold{85.0};
  double cpu_critical_threshold{95.0};

  // Memory threshold percentages for each level.
  double memory_light_threshold{60.0};
  double memory_moderate_threshold{75.0};
  double memory_severe_threshold{85.0};
  double memory_critical_threshold{95.0};

  // Connection count thresholds (percentage of max).
  double connections_moderate_threshold{80.0};
  double connections_severe_threshold{90.0};
  double connections_critical_threshold{95.0};

  // Hysteresis - percentage below threshold before recovery.
  double recovery_hysteresis{5.0};

  // Minimum time at a degradation level before escalating.
  std::chrono::seconds escalation_delay{5};

  // Minimum time before de-escalating.
  std::chrono::seconds recovery_delay{10};

  // Enable automatic degradation based on system metrics.
  bool auto_degrade{true};

  // Enable automatic recovery when load decreases.
  bool auto_recover{true};
};

// System resource metrics.
struct SystemMetrics {
  double cpu_usage_percent{0.0};
  double memory_usage_percent{0.0};
  std::size_t active_connections{0};
  std::size_t max_connections{0};
  std::size_t pending_packets{0};
  std::size_t max_packet_queue{0};
};

// Degradation actions to take at each level.
struct DegradationActions {
  // Heartbeat interval multiplier (1.0 = normal, 2.0 = double interval).
  double heartbeat_multiplier{1.0};
  // ACK batching factor (1 = immediate, 4 = batch up to 4).
  std::uint32_t ack_batch_factor{1};
  // Retransmit timeout multiplier.
  double retransmit_multiplier{1.0};
  // Whether to accept new connections.
  bool accept_new_connections{true};
  // Whether to drop low-priority traffic.
  bool drop_low_priority{false};
  // Maximum concurrent operations.
  std::optional<std::size_t> max_concurrent_ops;
};

// Get recommended actions for a degradation level.
DegradationActions get_default_actions(DegradationLevel level);

// Callbacks for degradation events.
struct DegradationCallbacks {
  // Called when degradation level changes.
  std::function<void(DegradationLevel old_level, DegradationLevel new_level)> on_level_change;
  // Called when entering degraded state.
  std::function<void(DegradationLevel level)> on_degraded;
  // Called when returning to normal.
  std::function<void()> on_recovered;
  // Called to request new connection rejection.
  std::function<void()> on_reject_connections;
};

// Graceful degradation controller.
class GracefulDegradation {
 public:
  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;

  explicit GracefulDegradation(DegradationConfig config = {},
                               DegradationCallbacks callbacks = {},
                               std::function<TimePoint()> now_fn = Clock::now);

  // Update system metrics and check for degradation.
  // Returns true if level changed.
  bool update(const SystemMetrics& metrics);

  // Manually set degradation level.
  void set_level(DegradationLevel level);

  // Get current degradation level.
  DegradationLevel level() const { return level_.load(std::memory_order_relaxed); }

  // Get recommended actions for current level.
  DegradationActions current_actions() const;

  // Check if system is degraded.
  bool is_degraded() const { return level() != DegradationLevel::kNormal; }

  // Check if new connections should be accepted.
  bool should_accept_connections() const;

  // Check if operation should be allowed based on priority.
  bool should_allow_operation(bool is_critical = false) const;

  // Get time since last level change.
  std::chrono::seconds time_since_level_change() const;

  // Get last metrics.
  const SystemMetrics& last_metrics() const { return last_metrics_; }

  // Get configuration.
  const DegradationConfig& config() const { return config_; }

  // Update configuration.
  void update_config(const DegradationConfig& config);

  // Statistics.
  struct Stats {
    std::uint64_t level_changes{0};
    std::uint64_t time_in_normal_ms{0};
    std::uint64_t time_in_degraded_ms{0};
    std::uint64_t connections_rejected{0};
    std::uint64_t operations_throttled{0};
  };
  Stats get_stats() const;

 private:
  DegradationLevel calculate_level(const SystemMetrics& metrics) const;
  bool should_escalate(DegradationLevel new_level) const;
  bool should_recover(DegradationLevel new_level) const;
  void transition_to(DegradationLevel new_level);

  DegradationConfig config_;
  DegradationCallbacks callbacks_;
  std::function<TimePoint()> now_fn_;

  std::atomic<DegradationLevel> level_{DegradationLevel::kNormal};
  TimePoint level_changed_at_;
  TimePoint last_escalation_check_;
  SystemMetrics last_metrics_;

  // Stats.
  std::atomic<std::uint64_t> level_changes_{0};
  std::atomic<std::uint64_t> time_in_normal_ms_{0};
  std::atomic<std::uint64_t> time_in_degraded_ms_{0};
  std::atomic<std::uint64_t> connections_rejected_{0};
  mutable std::atomic<std::uint64_t> operations_throttled_{0};

  mutable std::mutex mutex_;
};

// System resource monitor (platform-specific).
class SystemResourceMonitor {
 public:
  using Clock = std::chrono::steady_clock;

  explicit SystemResourceMonitor(std::function<Clock::time_point()> now_fn = Clock::now);

  // Get current system metrics.
  SystemMetrics get_metrics() const;

  // Get CPU usage percentage.
  double get_cpu_usage() const;

  // Get memory usage percentage.
  double get_memory_usage() const;

  // Set connection tracking.
  void set_connection_info(std::size_t active, std::size_t max);

  // Set packet queue tracking.
  void set_queue_info(std::size_t pending, std::size_t max);

 private:
  std::function<Clock::time_point()> now_fn_;
  std::atomic<std::size_t> active_connections_{0};
  std::atomic<std::size_t> max_connections_{0};
  std::atomic<std::size_t> pending_packets_{0};
  std::atomic<std::size_t> max_packet_queue_{0};

  // CPU tracking (simplified).
  mutable Clock::time_point last_cpu_check_;
  mutable double last_cpu_usage_{0.0};
  mutable std::mutex mutex_;
};

}  // namespace veil::utils
