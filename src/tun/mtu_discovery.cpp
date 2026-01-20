#include "tun/mtu_discovery.h"

#include <algorithm>

#include "common/logging/logger.h"

namespace veil::tun {

PmtuDiscovery::PmtuDiscovery(PmtuConfig config, std::function<TimePoint()> now_fn)
    : config_(std::move(config)), now_fn_(std::move(now_fn)) {}

PmtuDiscovery::PeerState& PmtuDiscovery::get_or_create_state(const std::string& peer) {
  auto it = peers_.find(peer);
  if (it == peers_.end()) {
    PeerState state;
    state.current_mtu = config_.initial_mtu;
    state.last_probe = now_fn_();
    it = peers_.emplace(peer, state).first;
  }
  return it->second;
}

const PmtuDiscovery::PeerState* PmtuDiscovery::get_state(const std::string& peer) const {
  auto it = peers_.find(peer);
  if (it == peers_.end()) {
    return nullptr;
  }
  return &it->second;
}

int PmtuDiscovery::get_mtu(const std::string& peer) const {
  const auto* state = get_state(peer);
  return (state != nullptr) ? state->current_mtu : config_.initial_mtu;
}

void PmtuDiscovery::set_mtu(const std::string& peer, int mtu) {
  auto& state = get_or_create_state(peer);
  const int old_mtu = state.current_mtu;

  // Clamp to valid range.
  mtu = std::clamp(mtu, config_.min_mtu, config_.max_mtu);

  if (mtu != old_mtu) {
    state.current_mtu = mtu;
    state.probing = false;
    state.probe_count = 0;
    notify_mtu_change(peer, old_mtu, mtu);
  }
}

void PmtuDiscovery::handle_fragmentation_needed(const std::string& peer, int next_hop_mtu) {
  auto& state = get_or_create_state(peer);
  const int old_mtu = state.current_mtu;

  int new_mtu = 0;
  if (next_hop_mtu > 0) {
    // Use the reported next-hop MTU.
    new_mtu = next_hop_mtu - kVeilOverhead;
  } else {
    // No MTU provided, use binary search to find it.
    // Reduce by ~20% as a starting point.
    new_mtu = (state.current_mtu * 4) / 5;
  }

  // Clamp to valid range.
  new_mtu = std::clamp(new_mtu, config_.min_mtu, old_mtu - 1);

  if (new_mtu < old_mtu) {
    state.current_mtu = new_mtu;
    state.last_decrease = now_fn_();
    state.probing = false;
    state.probe_count = 0;
    LOG_INFO("PMTU decreased for {}: {} -> {} (ICMP reported: {})", peer, old_mtu, new_mtu,
             next_hop_mtu);
    notify_mtu_change(peer, old_mtu, new_mtu);
  }
}

void PmtuDiscovery::handle_probe_success(const std::string& peer, int size) {
  auto& state = get_or_create_state(peer);

  if (state.probing && size >= state.probe_mtu) {
    // Probe succeeded, update MTU.
    const int old_mtu = state.current_mtu;
    state.current_mtu = size;
    state.probing = false;
    state.probe_count = 0;
    state.last_probe = now_fn_();
    LOG_INFO("PMTU increased for {}: {} -> {}", peer, old_mtu, size);
    notify_mtu_change(peer, old_mtu, size);
  }
}

void PmtuDiscovery::handle_probe_failure(const std::string& peer, int size) {
  auto& state = get_or_create_state(peer);

  if (state.probing && size == state.probe_mtu) {
    state.probe_count++;
    if (state.probe_count >= config_.max_probes) {
      // Give up probing at this size.
      state.probing = false;
      state.probe_count = 0;
      state.probe_mtu = 0;
      LOG_DEBUG("PMTU probe failed for {} at size {} after {} attempts", peer, size,
                config_.max_probes);
    }
  }
}

bool PmtuDiscovery::should_probe_increase(const std::string& peer) const {
  const auto* state = get_state(peer);
  if (state == nullptr) {
    return false;
  }

  // Don't probe if already at max MTU.
  if (state->current_mtu >= config_.max_mtu) {
    return false;
  }

  // Don't probe if currently probing.
  if (state->probing) {
    return false;
  }

  // Don't probe too soon after a decrease.
  const auto now = now_fn_();
  const auto time_since_decrease =
      std::chrono::duration_cast<std::chrono::seconds>(now - state->last_decrease);
  if (time_since_decrease < config_.probe_interval) {
    return false;
  }

  // Check if it's time to probe.
  const auto time_since_probe =
      std::chrono::duration_cast<std::chrono::seconds>(now - state->last_probe);
  return time_since_probe >= config_.probe_interval;
}

int PmtuDiscovery::get_next_probe_size(const std::string& peer) const {
  const auto* state = get_state(peer);
  const int current = (state != nullptr) ? state->current_mtu : config_.initial_mtu;

  // Try to increase by ~10%, capped at max.
  const int probe_size = std::min(current + (current / 10) + 10, config_.max_mtu);
  return probe_size;
}

void PmtuDiscovery::set_mtu_change_callback(MtuChangeCallback callback) {
  mtu_change_callback_ = std::move(callback);
}

int PmtuDiscovery::get_payload_size(const std::string& peer) const {
  return get_mtu(peer) - kVeilOverhead;
}

void PmtuDiscovery::reset(const std::string& peer) {
  auto& state = get_or_create_state(peer);
  const int old_mtu = state.current_mtu;
  state.current_mtu = config_.initial_mtu;
  state.probe_mtu = 0;
  state.probe_count = 0;
  state.probing = false;
  state.last_probe = now_fn_();
  state.last_decrease = TimePoint{};

  if (old_mtu != config_.initial_mtu) {
    notify_mtu_change(peer, old_mtu, config_.initial_mtu);
  }
}

void PmtuDiscovery::remove_peer(const std::string& peer) { peers_.erase(peer); }

void PmtuDiscovery::notify_mtu_change(const std::string& peer, int old_mtu, int new_mtu) {
  if (mtu_change_callback_) {
    mtu_change_callback_(peer, old_mtu, new_mtu);
  }
}

}  // namespace veil::tun
