#include "common/utils/graceful_degradation.h"

#include <algorithm>
#include <fstream>
#include <sstream>
#include <string>

namespace veil::utils {

const char* degradation_level_to_string(DegradationLevel level) {
  switch (level) {
    case DegradationLevel::kNormal:
      return "normal";
    case DegradationLevel::kLight:
      return "light";
    case DegradationLevel::kModerate:
      return "moderate";
    case DegradationLevel::kSevere:
      return "severe";
    case DegradationLevel::kCritical:
      return "critical";
    default:
      return "unknown";
  }
}

DegradationActions get_default_actions(DegradationLevel level) {
  DegradationActions actions;

  switch (level) {
    case DegradationLevel::kNormal:
      actions.heartbeat_multiplier = 1.0;
      actions.ack_batch_factor = 1;
      actions.retransmit_multiplier = 1.0;
      actions.accept_new_connections = true;
      actions.drop_low_priority = false;
      break;

    case DegradationLevel::kLight:
      actions.heartbeat_multiplier = 1.5;
      actions.ack_batch_factor = 2;
      actions.retransmit_multiplier = 1.2;
      actions.accept_new_connections = true;
      actions.drop_low_priority = false;
      break;

    case DegradationLevel::kModerate:
      actions.heartbeat_multiplier = 2.0;
      actions.ack_batch_factor = 4;
      actions.retransmit_multiplier = 1.5;
      actions.accept_new_connections = true;
      actions.drop_low_priority = true;
      break;

    case DegradationLevel::kSevere:
      actions.heartbeat_multiplier = 3.0;
      actions.ack_batch_factor = 8;
      actions.retransmit_multiplier = 2.0;
      actions.accept_new_connections = false;
      actions.drop_low_priority = true;
      break;

    case DegradationLevel::kCritical:
      actions.heartbeat_multiplier = 5.0;
      actions.ack_batch_factor = 16;
      actions.retransmit_multiplier = 3.0;
      actions.accept_new_connections = false;
      actions.drop_low_priority = true;
      actions.max_concurrent_ops = 10;
      break;
  }

  return actions;
}

// GracefulDegradation implementation.

GracefulDegradation::GracefulDegradation(DegradationConfig config, DegradationCallbacks callbacks,
                                         std::function<TimePoint()> now_fn)
    : config_(std::move(config)),
      callbacks_(std::move(callbacks)),
      now_fn_(std::move(now_fn)),
      level_changed_at_(now_fn_()),
      last_escalation_check_(now_fn_()) {}

bool GracefulDegradation::update(const SystemMetrics& metrics) {
  std::lock_guard<std::mutex> lock(mutex_);

  last_metrics_ = metrics;

  if (!config_.auto_degrade && !config_.auto_recover) {
    return false;
  }

  auto new_level = calculate_level(metrics);
  auto current = level_.load(std::memory_order_relaxed);

  // Track time in current state.
  auto now = now_fn_();
  auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(now - level_changed_at_);
  if (current == DegradationLevel::kNormal) {
    time_in_normal_ms_.fetch_add(static_cast<std::uint64_t>(duration.count()),
                                  std::memory_order_relaxed);
  } else {
    time_in_degraded_ms_.fetch_add(static_cast<std::uint64_t>(duration.count()),
                                   std::memory_order_relaxed);
  }

  if (new_level == current) {
    return false;
  }

  // Check if we should change level.
  if (new_level > current) {
    // Escalating.
    if (config_.auto_degrade && should_escalate(new_level)) {
      transition_to(new_level);
      return true;
    }
  } else {
    // Recovering.
    if (config_.auto_recover && should_recover(new_level)) {
      transition_to(new_level);
      return true;
    }
  }

  return false;
}

void GracefulDegradation::set_level(DegradationLevel level) {
  std::lock_guard<std::mutex> lock(mutex_);
  transition_to(level);
}

DegradationActions GracefulDegradation::current_actions() const {
  return get_default_actions(level_.load(std::memory_order_relaxed));
}

bool GracefulDegradation::should_accept_connections() const {
  return current_actions().accept_new_connections;
}

bool GracefulDegradation::should_allow_operation(bool is_critical) const {
  if (is_critical) {
    return true;
  }

  auto actions = current_actions();
  if (actions.drop_low_priority) {
    ++operations_throttled_;
    return false;
  }

  return true;
}

std::chrono::seconds GracefulDegradation::time_since_level_change() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return std::chrono::duration_cast<std::chrono::seconds>(now_fn_() - level_changed_at_);
}

void GracefulDegradation::update_config(const DegradationConfig& config) {
  std::lock_guard<std::mutex> lock(mutex_);
  config_ = config;
}

GracefulDegradation::Stats GracefulDegradation::get_stats() const {
  Stats stats;
  stats.level_changes = level_changes_.load(std::memory_order_relaxed);
  stats.time_in_normal_ms = time_in_normal_ms_.load(std::memory_order_relaxed);
  stats.time_in_degraded_ms = time_in_degraded_ms_.load(std::memory_order_relaxed);
  stats.connections_rejected = connections_rejected_.load(std::memory_order_relaxed);
  stats.operations_throttled = operations_throttled_.load(std::memory_order_relaxed);
  return stats;
}

DegradationLevel GracefulDegradation::calculate_level(const SystemMetrics& metrics) const {
  // Check CPU.
  if (metrics.cpu_usage_percent >= config_.cpu_critical_threshold) {
    return DegradationLevel::kCritical;
  }
  if (metrics.cpu_usage_percent >= config_.cpu_severe_threshold) {
    return DegradationLevel::kSevere;
  }
  if (metrics.cpu_usage_percent >= config_.cpu_moderate_threshold) {
    return DegradationLevel::kModerate;
  }
  if (metrics.cpu_usage_percent >= config_.cpu_light_threshold) {
    return DegradationLevel::kLight;
  }

  // Check memory.
  if (metrics.memory_usage_percent >= config_.memory_critical_threshold) {
    return DegradationLevel::kCritical;
  }
  if (metrics.memory_usage_percent >= config_.memory_severe_threshold) {
    return DegradationLevel::kSevere;
  }
  if (metrics.memory_usage_percent >= config_.memory_moderate_threshold) {
    return DegradationLevel::kModerate;
  }
  if (metrics.memory_usage_percent >= config_.memory_light_threshold) {
    return DegradationLevel::kLight;
  }

  // Check connections.
  if (metrics.max_connections > 0) {
    double conn_pct =
        (static_cast<double>(metrics.active_connections) / static_cast<double>(metrics.max_connections)) * 100.0;
    if (conn_pct >= config_.connections_critical_threshold) {
      return DegradationLevel::kCritical;
    }
    if (conn_pct >= config_.connections_severe_threshold) {
      return DegradationLevel::kSevere;
    }
    if (conn_pct >= config_.connections_moderate_threshold) {
      return DegradationLevel::kModerate;
    }
  }

  return DegradationLevel::kNormal;
}

bool GracefulDegradation::should_escalate([[maybe_unused]] DegradationLevel new_level) const {
  auto now = now_fn_();
  auto since_change = std::chrono::duration_cast<std::chrono::seconds>(now - level_changed_at_);

  // Must wait escalation delay before escalating.
  return since_change >= config_.escalation_delay;
}

bool GracefulDegradation::should_recover([[maybe_unused]] DegradationLevel new_level) const {
  auto now = now_fn_();
  auto since_change = std::chrono::duration_cast<std::chrono::seconds>(now - level_changed_at_);

  // Must wait recovery delay before recovering.
  if (since_change < config_.recovery_delay) {
    return false;
  }

  // Check hysteresis - metrics must be below threshold by hysteresis amount.
  auto level = level_.load(std::memory_order_relaxed);

  // Get threshold for current level.
  double cpu_threshold = 0.0;
  double mem_threshold = 0.0;

  switch (level) {
    case DegradationLevel::kLight:
      cpu_threshold = config_.cpu_light_threshold;
      mem_threshold = config_.memory_light_threshold;
      break;
    case DegradationLevel::kModerate:
      cpu_threshold = config_.cpu_moderate_threshold;
      mem_threshold = config_.memory_moderate_threshold;
      break;
    case DegradationLevel::kSevere:
      cpu_threshold = config_.cpu_severe_threshold;
      mem_threshold = config_.memory_severe_threshold;
      break;
    case DegradationLevel::kCritical:
      cpu_threshold = config_.cpu_critical_threshold;
      mem_threshold = config_.memory_critical_threshold;
      break;
    default:
      return true;
  }

  // Must be below threshold - hysteresis.
  return last_metrics_.cpu_usage_percent < (cpu_threshold - config_.recovery_hysteresis) &&
         last_metrics_.memory_usage_percent < (mem_threshold - config_.recovery_hysteresis);
}

void GracefulDegradation::transition_to(DegradationLevel new_level) {
  auto old_level = level_.exchange(new_level, std::memory_order_relaxed);

  if (old_level == new_level) {
    return;
  }

  level_changed_at_ = now_fn_();
  level_changes_.fetch_add(1, std::memory_order_relaxed);

  // Fire callbacks.
  if (callbacks_.on_level_change) {
    callbacks_.on_level_change(old_level, new_level);
  }

  if (new_level == DegradationLevel::kNormal) {
    if (callbacks_.on_recovered) {
      callbacks_.on_recovered();
    }
  } else if (old_level == DegradationLevel::kNormal) {
    if (callbacks_.on_degraded) {
      callbacks_.on_degraded(new_level);
    }
  }

  if (!get_default_actions(new_level).accept_new_connections && callbacks_.on_reject_connections) {
    callbacks_.on_reject_connections();
  }
}

// SystemResourceMonitor implementation.

SystemResourceMonitor::SystemResourceMonitor(std::function<Clock::time_point()> now_fn)
    : now_fn_(std::move(now_fn)), last_cpu_check_(now_fn_()) {}

SystemMetrics SystemResourceMonitor::get_metrics() const {
  SystemMetrics metrics;
  metrics.cpu_usage_percent = get_cpu_usage();
  metrics.memory_usage_percent = get_memory_usage();
  metrics.active_connections = active_connections_.load(std::memory_order_relaxed);
  metrics.max_connections = max_connections_.load(std::memory_order_relaxed);
  metrics.pending_packets = pending_packets_.load(std::memory_order_relaxed);
  metrics.max_packet_queue = max_packet_queue_.load(std::memory_order_relaxed);
  return metrics;
}

double SystemResourceMonitor::get_cpu_usage() const {
  // Read from /proc/stat on Linux.
  std::lock_guard<std::mutex> lock(mutex_);

  // Simple implementation - read /proc/loadavg for 1-minute load average.
  // In a real implementation, we'd track CPU time differences.
  std::ifstream loadavg("/proc/loadavg");
  if (!loadavg.is_open()) {
    return last_cpu_usage_;
  }

  double load1 = 0.0;
  loadavg >> load1;

  // Estimate CPU usage from load average (assuming number of CPUs).
  // This is a rough approximation.
  std::ifstream cpuinfo("/proc/cpuinfo");
  int num_cpus = 0;
  std::string line;
  while (std::getline(cpuinfo, line)) {
    if (line.starts_with("processor")) {
      num_cpus++;
    }
  }

  if (num_cpus == 0) {
    num_cpus = 1;
  }

  // Load of 1.0 per CPU = 100% usage.
  last_cpu_usage_ = std::min(100.0, (load1 / static_cast<double>(num_cpus)) * 100.0);
  last_cpu_check_ = now_fn_();

  return last_cpu_usage_;
}

double SystemResourceMonitor::get_memory_usage() const {
  // Read from /proc/meminfo on Linux.
  std::ifstream meminfo("/proc/meminfo");
  if (!meminfo.is_open()) {
    return 0.0;
  }

  std::uint64_t mem_total = 0;
  std::uint64_t mem_available = 0;
  std::string line;

  while (std::getline(meminfo, line)) {
    std::istringstream iss(line);
    std::string key;
    std::uint64_t value = 0;

    iss >> key >> value;

    if (key == "MemTotal:") {
      mem_total = value;
    } else if (key == "MemAvailable:") {
      mem_available = value;
    }
  }

  if (mem_total == 0) {
    return 0.0;
  }

  return (1.0 - static_cast<double>(mem_available) / static_cast<double>(mem_total)) * 100.0;
}

void SystemResourceMonitor::set_connection_info(std::size_t active, std::size_t max) {
  active_connections_.store(active, std::memory_order_relaxed);
  max_connections_.store(max, std::memory_order_relaxed);
}

void SystemResourceMonitor::set_queue_info(std::size_t pending, std::size_t max) {
  pending_packets_.store(pending, std::memory_order_relaxed);
  max_packet_queue_.store(max, std::memory_order_relaxed);
}

}  // namespace veil::utils
