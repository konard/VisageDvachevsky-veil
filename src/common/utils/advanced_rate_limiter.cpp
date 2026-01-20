#include "common/utils/advanced_rate_limiter.h"

#include <algorithm>

namespace veil::utils {

// BurstTokenBucket implementation.

BurstTokenBucket::BurstTokenBucket(std::uint64_t rate_per_sec, double burst_factor,
                                   std::chrono::milliseconds penalty_duration,
                                   std::function<Clock::time_point()> now_fn)
    : rate_per_sec_(rate_per_sec),
      burst_capacity_(static_cast<double>(rate_per_sec) * burst_factor),
      tokens_(burst_capacity_),
      penalty_duration_(penalty_duration),
      now_fn_(std::move(now_fn)),
      last_refill_(now_fn_()),
      penalty_end_() {}

bool BurstTokenBucket::try_consume(std::uint64_t tokens) {
  refill();

  // Check if in penalty period.
  if (in_penalty_ && now_fn_() < penalty_end_) {
    return false;
  }
  in_penalty_ = false;

  auto requested = static_cast<double>(tokens);
  if (tokens_ >= requested) {
    tokens_ -= requested;
    return true;
  }

  // Not enough tokens - enter penalty if burst was exhausted.
  if (tokens_ < burst_capacity_ * 0.1) {
    in_penalty_ = true;
    penalty_end_ = now_fn_() + penalty_duration_;
  }

  return false;
}

bool BurstTokenBucket::is_penalized() const {
  return in_penalty_ && now_fn_() < penalty_end_;
}

void BurstTokenBucket::reset() {
  tokens_ = burst_capacity_;
  last_refill_ = now_fn_();
  in_penalty_ = false;
}

void BurstTokenBucket::refill() {
  auto now = now_fn_();
  auto elapsed = std::chrono::duration<double>(now - last_refill_);
  double refill_amount = elapsed.count() * static_cast<double>(rate_per_sec_);
  tokens_ = std::min(tokens_ + refill_amount, burst_capacity_);
  last_refill_ = now;
}

// ClientRateLimiter implementation.

ClientRateLimiter::ClientRateLimiter(const RateLimiterConfig& config,
                                     std::function<Clock::time_point()> now_fn)
    : config_(config),
      now_fn_(std::move(now_fn)),
      bandwidth_bucket_(config.bandwidth_bytes_per_sec, config.burst_allowance_factor,
                        config.burst_penalty_duration, now_fn_),
      packet_bucket_(config.packets_per_sec, config.burst_allowance_factor,
                     config.burst_penalty_duration, now_fn_) {
  stats_.last_activity = now_fn_();
}

bool ClientRateLimiter::allow_packet(std::uint64_t size_bytes, TrafficPriority priority) {
  stats_.last_activity = now_fn_();

  // Critical traffic always allowed (but still counted).
  if (priority == TrafficPriority::kCritical) {
    // Still try to consume to track usage, but allow anyway.
    bandwidth_bucket_.try_consume(size_bytes);
    packet_bucket_.try_consume(1);
    stats_.bytes_allowed += size_bytes;
    stats_.packets_allowed++;
    return true;
  }

  // Check bandwidth limit.
  bool bandwidth_ok = bandwidth_bucket_.try_consume(size_bytes);
  if (!bandwidth_ok) {
    stats_.bytes_denied += size_bytes;
    stats_.violations++;
    stats_.last_violation = now_fn_();
    return false;
  }

  // Check packet rate limit.
  bool packet_ok = packet_bucket_.try_consume(1);
  if (!packet_ok) {
    // Refund bandwidth since we're denying.
    stats_.packets_denied++;
    stats_.violations++;
    stats_.last_violation = now_fn_();
    return false;
  }

  stats_.bytes_allowed += size_bytes;
  stats_.packets_allowed++;
  return true;
}

bool ClientRateLimiter::record_reconnect() {
  auto now = now_fn_();
  stats_.reconnects++;

  cleanup_reconnect_history();
  reconnect_history_.push_back(now);

  if (reconnect_history_.size() > config_.max_reconnects_per_minute) {
    stats_.violations++;
    stats_.last_violation = now;
    return false;
  }

  return true;
}

bool ClientRateLimiter::is_blocked() const {
  // Block if too many violations in the tracking window.
  auto now = now_fn_();

  // Simple heuristic: block if more than 100 violations in the window.
  // and last violation was recent.
  if (stats_.violations > 100) {
    auto since_violation = std::chrono::duration_cast<std::chrono::seconds>(now - stats_.last_violation);
    if (since_violation < config_.violation_tracking_window) {
      return true;
    }
  }

  return false;
}

std::uint64_t ClientRateLimiter::remaining_bandwidth() const {
  return static_cast<std::uint64_t>(bandwidth_bucket_.current_tokens());
}

std::uint64_t ClientRateLimiter::remaining_packets() const {
  return static_cast<std::uint64_t>(packet_bucket_.current_tokens());
}

void ClientRateLimiter::cleanup_reconnect_history() {
  auto now = now_fn_();
  auto cutoff = now - std::chrono::minutes(1);

  while (!reconnect_history_.empty() && reconnect_history_.front() < cutoff) {
    reconnect_history_.pop_front();
  }
}

// AdvancedRateLimiter implementation.

AdvancedRateLimiter::AdvancedRateLimiter(RateLimiterConfig config,
                                         std::function<Clock::time_point()> now_fn)
    : default_config_(std::move(config)), now_fn_(std::move(now_fn)) {}

void AdvancedRateLimiter::set_client_config(const ClientId& client_id,
                                             const RateLimiterConfig& config) {
  client_configs_[client_id] = config;

  // If client already exists, recreate with new config.
  auto it = clients_.find(client_id);
  if (it != clients_.end()) {
    clients_.erase(it);
  }
}

bool AdvancedRateLimiter::allow_packet(const ClientId& client_id, std::uint64_t size_bytes,
                                        TrafficPriority priority) {
  auto& client = get_or_create_client(client_id);

  if (client.is_blocked()) {
    return false;
  }

  return client.allow_packet(size_bytes, priority);
}

bool AdvancedRateLimiter::record_reconnect(const ClientId& client_id) {
  auto& client = get_or_create_client(client_id);
  return client.record_reconnect();
}

void AdvancedRateLimiter::remove_client(const ClientId& client_id) {
  clients_.erase(client_id);
  client_configs_.erase(client_id);
}

std::optional<ClientRateLimitStats> AdvancedRateLimiter::get_client_stats(
    const ClientId& client_id) const {
  auto it = clients_.find(client_id);
  if (it == clients_.end()) {
    return std::nullopt;
  }
  return it->second->stats();
}

AdvancedRateLimiter::GlobalStats AdvancedRateLimiter::get_global_stats() const {
  GlobalStats stats;
  stats.tracked_clients = clients_.size();

  for (const auto& [id, client] : clients_) {
    const auto& client_stats = client->stats();
    stats.total_bytes_allowed += client_stats.bytes_allowed;
    stats.total_bytes_denied += client_stats.bytes_denied;
    stats.total_packets_allowed += client_stats.packets_allowed;
    stats.total_packets_denied += client_stats.packets_denied;
    stats.total_violations += client_stats.violations;
    if (client->is_blocked()) {
      stats.blocked_clients++;
    }
  }

  return stats;
}

std::size_t AdvancedRateLimiter::cleanup_inactive(std::chrono::seconds max_idle) {
  auto now = now_fn_();
  std::size_t removed = 0;

  for (auto it = clients_.begin(); it != clients_.end();) {
    auto idle_time = std::chrono::duration_cast<std::chrono::seconds>(
        now - it->second->stats().last_activity);
    if (idle_time > max_idle) {
      client_configs_.erase(it->first);
      it = clients_.erase(it);
      removed++;
    } else {
      ++it;
    }
  }

  return removed;
}

ClientRateLimiter& AdvancedRateLimiter::get_or_create_client(const ClientId& client_id) {
  auto it = clients_.find(client_id);
  if (it != clients_.end()) {
    return *it->second;
  }

  // Use custom config if available, otherwise default.
  auto config_it = client_configs_.find(client_id);
  const auto& config = (config_it != client_configs_.end()) ? config_it->second : default_config_;

  auto client = std::make_unique<ClientRateLimiter>(config, now_fn_);
  auto& ref = *client;
  clients_[client_id] = std::move(client);
  return ref;
}

}  // namespace veil::utils
