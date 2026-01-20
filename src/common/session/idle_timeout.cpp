#include "common/session/idle_timeout.h"

namespace veil::session {

const char* idle_timeout_level_to_string(IdleTimeoutLevel level) {
  switch (level) {
    case IdleTimeoutLevel::kNone:
      return "none";
    case IdleTimeoutLevel::kWarning:
      return "warning";
    case IdleTimeoutLevel::kSoftClose:
      return "soft_close";
    case IdleTimeoutLevel::kForcedClose:
      return "forced_close";
    default:
      return "unknown";
  }
}

// IdleTimeout implementation.

IdleTimeout::IdleTimeout(IdleTimeoutConfig config, IdleTimeoutCallbacks callbacks,
                         std::function<TimePoint()> now_fn)
    : config_(std::move(config)), callbacks_(std::move(callbacks)), now_fn_(std::move(now_fn)) {
  auto now = now_fn_();
  last_rx_ = now;
  last_tx_ = now;
  last_heartbeat_ = now;
  last_activity_ = now;
  last_keepalive_sent_ = now;
  last_keepalive_response_ = now;
}

void IdleTimeout::record_activity(ActivityType type) {
  auto now = now_fn_();

  switch (type) {
    case ActivityType::kReceive:
      last_rx_ = now;
      break;
    case ActivityType::kTransmit:
      last_tx_ = now;
      break;
    case ActivityType::kHeartbeat:
      last_heartbeat_ = now;
      break;
    case ActivityType::kKeepalive:
      record_keepalive_response();
      return;  // Handled separately.
    case ActivityType::kAny:
      break;
  }

  last_activity_ = now;

  // Reset idle state on activity.
  if (current_level_ != IdleTimeoutLevel::kNone) {
    current_level_ = IdleTimeoutLevel::kNone;
    warning_triggered_ = false;
    soft_close_triggered_ = false;
  }
}

void IdleTimeout::record_keepalive_response() {
  auto now = now_fn_();
  last_keepalive_response_ = now;
  last_activity_ = now;
  missed_probes_ = 0;

  if (current_level_ != IdleTimeoutLevel::kNone) {
    current_level_ = IdleTimeoutLevel::kNone;
    warning_triggered_ = false;
    soft_close_triggered_ = false;
  }
}

void IdleTimeout::record_keepalive_sent() {
  last_keepalive_sent_ = now_fn_();
}

IdleTimeoutLevel IdleTimeout::check() {
  auto now = now_fn_();
  auto idle = std::chrono::duration_cast<std::chrono::seconds>(now - last_activity_);

  // Check keep-alive probes.
  if (config_.enable_keepalive) {
    check_keepalive();
  }

  // Check forced close threshold.
  if (idle >= config_.forced_close_threshold) {
    if (current_level_ != IdleTimeoutLevel::kForcedClose) {
      current_level_ = IdleTimeoutLevel::kForcedClose;
      if (callbacks_.on_forced_close) {
        callbacks_.on_forced_close();
      }
    }
    return current_level_;
  }

  // Check soft close threshold.
  if (idle >= config_.soft_close_threshold) {
    if (!soft_close_triggered_) {
      current_level_ = IdleTimeoutLevel::kSoftClose;
      soft_close_triggered_ = true;
      if (callbacks_.on_soft_close) {
        callbacks_.on_soft_close();
      }
    }
    return current_level_;
  }

  // Check warning threshold.
  if (idle >= config_.warning_threshold) {
    if (!warning_triggered_) {
      current_level_ = IdleTimeoutLevel::kWarning;
      warning_triggered_ = true;
      if (callbacks_.on_warning) {
        callbacks_.on_warning();
      }
    }
    return current_level_;
  }

  return IdleTimeoutLevel::kNone;
}

IdleTimeoutLevel IdleTimeout::current_level() const {
  auto now = now_fn_();
  auto idle = std::chrono::duration_cast<std::chrono::seconds>(now - last_activity_);

  if (idle >= config_.forced_close_threshold) {
    return IdleTimeoutLevel::kForcedClose;
  }
  if (idle >= config_.soft_close_threshold) {
    return IdleTimeoutLevel::kSoftClose;
  }
  if (idle >= config_.warning_threshold) {
    return IdleTimeoutLevel::kWarning;
  }
  return IdleTimeoutLevel::kNone;
}

bool IdleTimeout::should_send_keepalive() const {
  if (!config_.enable_keepalive) {
    return false;
  }

  auto now = now_fn_();
  auto since_last_probe =
      std::chrono::duration_cast<std::chrono::seconds>(now - last_keepalive_sent_);
  return since_last_probe >= config_.keepalive_interval;
}

bool IdleTimeout::is_connection_dead() const {
  return missed_probes_ >= config_.max_missed_probes;
}

std::chrono::seconds IdleTimeout::idle_duration() const {
  return std::chrono::duration_cast<std::chrono::seconds>(now_fn_() - last_activity_);
}

std::chrono::seconds IdleTimeout::time_until_next_level() const {
  auto idle = idle_duration();

  if (idle >= config_.forced_close_threshold) {
    return std::chrono::seconds(0);
  }
  if (idle >= config_.soft_close_threshold) {
    return config_.forced_close_threshold - idle;
  }
  if (idle >= config_.warning_threshold) {
    return config_.soft_close_threshold - idle;
  }
  return config_.warning_threshold - idle;
}

void IdleTimeout::reset() {
  auto now = now_fn_();
  last_rx_ = now;
  last_tx_ = now;
  last_heartbeat_ = now;
  last_activity_ = now;
  last_keepalive_sent_ = now;
  last_keepalive_response_ = now;
  current_level_ = IdleTimeoutLevel::kNone;
  missed_probes_ = 0;
  warning_triggered_ = false;
  soft_close_triggered_ = false;
}

void IdleTimeout::check_keepalive() {
  if (!config_.enable_keepalive) {
    return;
  }

  // Check if we should send a probe.
  if (should_send_keepalive()) {
    // Check if we're waiting for a response.
    if (last_keepalive_sent_ > last_keepalive_response_) {
      missed_probes_++;
      if (missed_probes_ >= config_.max_missed_probes && callbacks_.on_connection_dead) {
        callbacks_.on_connection_dead();
      }
    }

    // Request probe be sent.
    if (callbacks_.on_send_keepalive) {
      callbacks_.on_send_keepalive();
    }
  }
}

// KeepaliveManager implementation.

KeepaliveManager::KeepaliveManager(std::chrono::seconds probe_interval,
                                   std::function<TimePoint()> now_fn)
    : probe_interval_(probe_interval), now_fn_(std::move(now_fn)), last_check_(now_fn_()) {}

void KeepaliveManager::register_session(SessionId session_id, IdleTimeout* timeout) {
  sessions_[session_id] = timeout;
}

void KeepaliveManager::unregister_session(SessionId session_id) {
  sessions_.erase(session_id);
}

void KeepaliveManager::set_send_probe_callback(SendProbeCallback callback) {
  send_probe_callback_ = std::move(callback);
}

std::size_t KeepaliveManager::check_and_send_probes() {
  auto now = now_fn_();
  auto since_last = std::chrono::duration_cast<std::chrono::seconds>(now - last_check_);

  // Only check at probe interval.
  if (since_last < probe_interval_) {
    return 0;
  }
  last_check_ = now;

  std::size_t probes_sent = 0;

  for (auto& [session_id, timeout] : sessions_) {
    if (timeout->should_send_keepalive()) {
      if (send_probe_callback_) {
        send_probe_callback_(session_id);
        timeout->record_keepalive_sent();
        probes_sent++;
      }
    }
  }

  return probes_sent;
}

std::vector<KeepaliveManager::SessionId> KeepaliveManager::get_dead_sessions() const {
  std::vector<SessionId> dead;

  for (const auto& [session_id, timeout] : sessions_) {
    if (timeout->is_connection_dead()) {
      dead.push_back(session_id);
    }
  }

  return dead;
}

}  // namespace veil::session
