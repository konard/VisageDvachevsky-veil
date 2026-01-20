#include "common/session/session_lifecycle.h"

#include <algorithm>

namespace veil::session {

const char* session_state_to_string(SessionState state) {
  switch (state) {
    case SessionState::kActive:
      return "active";
    case SessionState::kDraining:
      return "draining";
    case SessionState::kExpired:
      return "expired";
    case SessionState::kTerminated:
      return "terminated";
    default:
      return "unknown";
  }
}

// SessionLifecycle implementation.

SessionLifecycle::SessionLifecycle(SessionId session_id, const SessionLifecycleConfig& config,
                                   SessionLifecycleCallbacks callbacks,
                                   std::function<TimePoint()> now_fn)
    : session_id_(session_id),
      config_(config),
      callbacks_(std::move(callbacks)),
      now_fn_(std::move(now_fn)),
      created_at_(now_fn_()) {
  stats_.created_at = created_at_;
  stats_.last_activity = created_at_;
  stats_.last_rx = created_at_;
  stats_.last_tx = created_at_;
}

void SessionLifecycle::record_activity() {
  if (state_ == SessionState::kActive) {
    stats_.last_activity = now_fn_();
  }
}

void SessionLifecycle::record_rx(std::size_t bytes) {
  stats_.bytes_received += bytes;
  stats_.packets_received++;
  stats_.last_rx = now_fn_();
  record_activity();
}

void SessionLifecycle::record_tx(std::size_t bytes) {
  stats_.bytes_sent += bytes;
  stats_.packets_sent++;
  stats_.last_tx = now_fn_();
  record_activity();
}

void SessionLifecycle::update_memory_usage(std::size_t bytes) {
  stats_.current_memory = bytes;
  stats_.peak_memory = std::max(stats_.peak_memory, bytes);

  if (bytes > config_.max_memory_per_session && callbacks_.on_memory_exceeded) {
    callbacks_.on_memory_exceeded(session_id_, bytes, config_.max_memory_per_session);
  }
}

void SessionLifecycle::record_queued_packet() {
  stats_.current_queue_size++;
  stats_.peak_queue_size = std::max(stats_.peak_queue_size, stats_.current_queue_size);

  if (stats_.current_queue_size > config_.max_packet_queue && callbacks_.on_queue_full) {
    callbacks_.on_queue_full(session_id_, stats_.current_queue_size);
  }
}

void SessionLifecycle::record_dequeued_packet() {
  if (stats_.current_queue_size > 0) {
    stats_.current_queue_size--;
  }
}

bool SessionLifecycle::check_timeouts() {
  if (state_ == SessionState::kExpired || state_ == SessionState::kTerminated) {
    return false;
  }

  auto now = now_fn_();

  // Check absolute timeout.
  auto session_age = std::chrono::duration_cast<std::chrono::seconds>(now - created_at_);
  if (session_age >= config_.absolute_timeout) {
    transition_to(SessionState::kExpired);
    return true;
  }

  // Handle draining state.
  if (state_ == SessionState::kDraining) {
    auto drain_duration = std::chrono::duration_cast<std::chrono::seconds>(now - drain_started_);
    if (drain_duration >= config_.drain_timeout) {
      transition_to(SessionState::kExpired);
      return true;
    }
    return false;
  }

  // Check idle timeout (only for active sessions).
  if (state_ == SessionState::kActive) {
    auto idle_time = std::chrono::duration_cast<std::chrono::seconds>(now - stats_.last_activity);

    // Check for idle expiry.
    if (idle_time >= config_.idle_timeout) {
      transition_to(SessionState::kExpired);
      return true;
    }

    // Check for idle warning.
    if (idle_time >= config_.idle_warning && callbacks_.on_idle_warning) {
      callbacks_.on_idle_warning(session_id_);
    }
  }

  return false;
}

void SessionLifecycle::start_drain() {
  if (state_ == SessionState::kActive) {
    drain_started_ = now_fn_();
    transition_to(SessionState::kDraining);
  }
}

void SessionLifecycle::terminate() {
  if (state_ != SessionState::kTerminated) {
    transition_to(SessionState::kTerminated);
  }
}

bool SessionLifecycle::can_accept_data() const {
  return state_ == SessionState::kActive;
}

bool SessionLifecycle::is_alive() const {
  return state_ == SessionState::kActive || state_ == SessionState::kDraining;
}

std::chrono::seconds SessionLifecycle::time_until_idle_timeout() const {
  if (state_ != SessionState::kActive) {
    return std::chrono::seconds(0);
  }

  auto now = now_fn_();
  auto idle_time = std::chrono::duration_cast<std::chrono::seconds>(now - stats_.last_activity);
  if (idle_time >= config_.idle_timeout) {
    return std::chrono::seconds(0);
  }

  return config_.idle_timeout - idle_time;
}

std::chrono::seconds SessionLifecycle::time_until_absolute_timeout() const {
  auto now = now_fn_();
  auto session_age = std::chrono::duration_cast<std::chrono::seconds>(now - created_at_);
  if (session_age >= config_.absolute_timeout) {
    return std::chrono::seconds(0);
  }

  return config_.absolute_timeout - session_age;
}

std::chrono::seconds SessionLifecycle::age() const {
  return std::chrono::duration_cast<std::chrono::seconds>(now_fn_() - created_at_);
}

void SessionLifecycle::transition_to(SessionState new_state) {
  if (state_ == new_state) {
    return;
  }

  state_ = new_state;

  switch (new_state) {
    case SessionState::kDraining:
      if (callbacks_.on_draining) {
        callbacks_.on_draining(session_id_);
      }
      break;
    case SessionState::kExpired:
      if (callbacks_.on_expired) {
        callbacks_.on_expired(session_id_);
      }
      break;
    case SessionState::kTerminated:
      if (callbacks_.on_terminated) {
        callbacks_.on_terminated(session_id_);
      }
      break;
    default:
      break;
  }
}

// SessionLifecycleManager implementation.

SessionLifecycleManager::SessionLifecycleManager(SessionLifecycleConfig config,
                                                  std::function<TimePoint()> now_fn)
    : config_(std::move(config)), now_fn_(std::move(now_fn)) {}

void SessionLifecycleManager::set_default_callbacks(SessionLifecycleCallbacks callbacks) {
  default_callbacks_ = std::move(callbacks);
}

SessionLifecycle& SessionLifecycleManager::create_session(SessionId session_id) {
  auto lifecycle = std::make_unique<SessionLifecycle>(session_id, config_, default_callbacks_, now_fn_);
  auto& ref = *lifecycle;
  sessions_[session_id] = std::move(lifecycle);
  return ref;
}

SessionLifecycle* SessionLifecycleManager::get_session(SessionId session_id) {
  auto it = sessions_.find(session_id);
  if (it == sessions_.end()) {
    return nullptr;
  }
  return it->second.get();
}

bool SessionLifecycleManager::remove_session(SessionId session_id) {
  return sessions_.erase(session_id) > 0;
}

std::vector<SessionLifecycleManager::SessionId> SessionLifecycleManager::check_all_timeouts() {
  std::vector<SessionId> changed;

  for (auto& [id, lifecycle] : sessions_) {
    if (lifecycle->check_timeouts()) {
      changed.push_back(id);
    }
  }

  return changed;
}

void SessionLifecycleManager::drain_all() {
  for (auto& [id, lifecycle] : sessions_) {
    lifecycle->start_drain();
  }
}

void SessionLifecycleManager::terminate_all() {
  for (auto& [id, lifecycle] : sessions_) {
    lifecycle->terminate();
  }
}

std::size_t SessionLifecycleManager::cleanup() {
  std::size_t removed = 0;

  for (auto it = sessions_.begin(); it != sessions_.end();) {
    auto state = it->second->state();
    if (state == SessionState::kExpired || state == SessionState::kTerminated) {
      it = sessions_.erase(it);
      removed++;
    } else {
      ++it;
    }
  }

  return removed;
}

SessionLifecycleManager::SessionCounts SessionLifecycleManager::get_counts() const {
  SessionCounts counts;
  counts.total = sessions_.size();

  for (const auto& [id, lifecycle] : sessions_) {
    switch (lifecycle->state()) {
      case SessionState::kActive:
        counts.active++;
        break;
      case SessionState::kDraining:
        counts.draining++;
        break;
      case SessionState::kExpired:
        counts.expired++;
        break;
      case SessionState::kTerminated:
        counts.terminated++;
        break;
    }
  }

  return counts;
}

std::vector<SessionLifecycleManager::SessionId> SessionLifecycleManager::get_sessions_in_state(
    SessionState state) const {
  std::vector<SessionId> result;

  for (const auto& [id, lifecycle] : sessions_) {
    if (lifecycle->state() == state) {
      result.push_back(id);
    }
  }

  return result;
}

}  // namespace veil::session
