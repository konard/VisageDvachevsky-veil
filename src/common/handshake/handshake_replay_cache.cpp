#include "common/handshake/handshake_replay_cache.h"

#include <algorithm>
#include <mutex>

namespace veil::handshake {

HandshakeReplayCache::HandshakeReplayCache(std::size_t capacity,
                                           std::chrono::milliseconds time_window)
    : capacity_(capacity), time_window_(time_window) {
  if (capacity_ == 0) {
    throw std::invalid_argument("replay cache capacity must be > 0");
  }
}

bool HandshakeReplayCache::mark_and_check(
    std::uint64_t timestamp_ms,
    const std::array<std::uint8_t, crypto::kX25519PublicKeySize>& ephemeral_key) {
  std::lock_guard<std::mutex> lock(mutex_);

  // Cleanup expired entries periodically (every ~100 insertions on average)
  // This is a simple heuristic to avoid cleanup overhead on every call
  static thread_local std::size_t call_count = 0;
  if (++call_count % 100 == 0) {
    cleanup_expired_locked(timestamp_ms);
  }

  CacheKey key{.timestamp_ms = timestamp_ms, .ephemeral_key = ephemeral_key};

  // Check if this key already exists (replay detected)
  auto it = cache_map_.find(key);
  if (it != cache_map_.end()) {
    // Move to back of LRU list (most recently used)
    lru_list_.splice(lru_list_.end(), lru_list_, it->second);
    return true;  // Replay detected
  }

  // New key - add to cache
  // If at capacity, evict LRU entry
  if (cache_map_.size() >= capacity_) {
    evict_lru();
  }

  // Add to back of LRU list (most recently used)
  lru_list_.push_back(key);
  auto list_it = std::prev(lru_list_.end());
  cache_map_[key] = list_it;

  return false;  // Not a replay
}

std::size_t HandshakeReplayCache::cleanup_expired(std::uint64_t current_time_ms) {
  std::lock_guard<std::mutex> lock(mutex_);
  return cleanup_expired_locked(current_time_ms);
}

std::size_t HandshakeReplayCache::cleanup_expired_locked(std::uint64_t current_time_ms) {
  // Assumes mutex is already held by caller
  std::size_t removed = 0;
  const std::uint64_t cutoff_ms =
      current_time_ms > static_cast<std::uint64_t>(time_window_.count())
          ? current_time_ms - static_cast<std::uint64_t>(time_window_.count())
          : 0;

  // Remove entries with timestamps older than cutoff
  auto it = lru_list_.begin();
  while (it != lru_list_.end()) {
    if (it->timestamp_ms < cutoff_ms) {
      cache_map_.erase(*it);
      it = lru_list_.erase(it);
      ++removed;
    } else {
      ++it;
    }
  }

  return removed;
}

std::size_t HandshakeReplayCache::size() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return cache_map_.size();
}

void HandshakeReplayCache::clear() {
  std::lock_guard<std::mutex> lock(mutex_);
  lru_list_.clear();
  cache_map_.clear();
}

void HandshakeReplayCache::evict_lru() {
  // Assumes mutex is already held by caller
  if (lru_list_.empty()) {
    return;
  }

  // Remove least recently used (front of list)
  const CacheKey& lru_key = lru_list_.front();
  cache_map_.erase(lru_key);
  lru_list_.pop_front();
}

}  // namespace veil::handshake
