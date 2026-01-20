#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <list>
#include <mutex>
#include <optional>
#include <unordered_map>

#include "common/crypto/crypto_engine.h"

namespace veil::handshake {

/**
 * LRU Replay Cache for handshake INIT messages.
 *
 * Prevents replay attacks by tracking recently seen (timestamp, ephemeral_public_key) pairs.
 * When an INIT packet arrives:
 * 1. Check if timestamp is within valid window
 * 2. Check if (timestamp, ephemeral_key) pair was seen before
 * 3. If duplicate, silently drop (anti-probing requirement)
 *
 * Implementation details:
 * - Fixed capacity with LRU eviction policy
 * - O(1) lookup, insert, and eviction operations
 * - Automatic cleanup of expired entries
 *
 * Thread Safety:
 *   This class IS thread-safe. All public methods are protected by an internal
 *   mutex, allowing safe concurrent access from multiple threads. This is
 *   necessary because handshake processing may occur on different threads
 *   than the main event loop.
 *
 *   Note: This is one of the few classes in VEIL that provides internal
 *   synchronization. Most other components rely on single-threaded access
 *   patterns enforced by the event loop.
 *
 * @see docs/thread_model.md for the VEIL threading model documentation.
 */
class HandshakeReplayCache {
 public:
  /**
   * Entry identifier combining timestamp and ephemeral public key.
   * This uniquely identifies each handshake INIT message.
   */
  struct CacheKey {
    std::uint64_t timestamp_ms;
    std::array<std::uint8_t, crypto::kX25519PublicKeySize> ephemeral_key;

    bool operator==(const CacheKey& other) const {
      return timestamp_ms == other.timestamp_ms && ephemeral_key == other.ephemeral_key;
    }
  };

  /**
   * Hash function for CacheKey to use in unordered_map.
   */
  struct CacheKeyHash {
    std::size_t operator()(const CacheKey& key) const noexcept {
      // Combine timestamp hash with first 8 bytes of ephemeral key
      std::size_t hash = std::hash<std::uint64_t>{}(key.timestamp_ms);

      // Mix in ephemeral key bytes (use first 8 bytes for efficiency)
      std::uint64_t key_prefix = 0;
      for (std::size_t i = 0; i < 8 && i < key.ephemeral_key.size(); ++i) {
        key_prefix = (key_prefix << 8) | key.ephemeral_key[i];
      }
      hash ^= std::hash<std::uint64_t>{}(key_prefix) + 0x9e3779b9 + (hash << 6) + (hash >> 2);

      return hash;
    }
  };

  /**
   * Construct replay cache with specified capacity and time window.
   *
   * @param capacity Maximum number of entries to cache (default: 4096)
   * @param time_window_ms Maximum age of entries in milliseconds (default: 60000ms = 60s)
   */
  explicit HandshakeReplayCache(
      std::size_t capacity = 4096,
      std::chrono::milliseconds time_window = std::chrono::milliseconds(60000));

  /**
   * Check if an INIT message is a replay and mark it as seen.
   *
   * @param timestamp_ms Timestamp from INIT message
   * @param ephemeral_key Ephemeral public key from INIT message
   * @return true if this is a replay (seen before), false if new
   *
   * Thread-safe: Multiple threads can call this concurrently.
   */
  bool mark_and_check(std::uint64_t timestamp_ms,
                      const std::array<std::uint8_t, crypto::kX25519PublicKeySize>& ephemeral_key);

  /**
   * Remove entries older than the time window.
   * Called automatically during mark_and_check, but can be called manually for cleanup.
   *
   * @param current_time_ms Current time in milliseconds
   * @return Number of entries removed
   */
  std::size_t cleanup_expired(std::uint64_t current_time_ms);

  /**
   * Get current number of cached entries.
   */
  [[nodiscard]] std::size_t size() const;

  /**
   * Get maximum capacity of the cache.
   */
  [[nodiscard]] std::size_t capacity() const { return capacity_; }

  /**
   * Clear all entries from the cache.
   */
  void clear();

 private:
  using LruList = std::list<CacheKey>;
  using LruIterator = LruList::iterator;
  using CacheMap = std::unordered_map<CacheKey, LruIterator, CacheKeyHash>;

  void evict_lru();
  void touch(const CacheKey& key);
  std::size_t cleanup_expired_locked(std::uint64_t current_time_ms);

  const std::size_t capacity_;
  const std::chrono::milliseconds time_window_;

  LruList lru_list_;           // Most recently used at back, least recently used at front
  CacheMap cache_map_;         // Maps CacheKey -> position in LRU list

  mutable std::mutex mutex_;   // Protects all internal state
};

}  // namespace veil::handshake
