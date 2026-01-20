#include "common/handshake/handshake_replay_cache.h"

#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <thread>

namespace veil::handshake::test {

class HandshakeReplayCacheTest : public ::testing::Test {
 protected:
  static std::array<std::uint8_t, crypto::kX25519PublicKeySize> make_key(std::uint8_t value) {
    std::array<std::uint8_t, crypto::kX25519PublicKeySize> key{};
    key.fill(value);
    return key;
  }
};

TEST_F(HandshakeReplayCacheTest, DetectsReplayWithSameTimestampAndKey) {
  HandshakeReplayCache cache(100);
  const auto key = make_key(0x42);
  const std::uint64_t ts = 1000;

  // First call should not detect replay
  EXPECT_FALSE(cache.mark_and_check(ts, key));

  // Second call with same timestamp and key should detect replay
  EXPECT_TRUE(cache.mark_and_check(ts, key));

  // Third call should still detect replay
  EXPECT_TRUE(cache.mark_and_check(ts, key));
}

TEST_F(HandshakeReplayCacheTest, AllowsDifferentKeys) {
  HandshakeReplayCache cache(100);
  const auto key1 = make_key(0x01);
  const auto key2 = make_key(0x02);
  const std::uint64_t ts = 1000;

  // First key
  EXPECT_FALSE(cache.mark_and_check(ts, key1));

  // Different key with same timestamp - should be allowed
  EXPECT_FALSE(cache.mark_and_check(ts, key2));

  // Replay first key
  EXPECT_TRUE(cache.mark_and_check(ts, key1));

  // Replay second key
  EXPECT_TRUE(cache.mark_and_check(ts, key2));
}

TEST_F(HandshakeReplayCacheTest, AllowsDifferentTimestamps) {
  HandshakeReplayCache cache(100);
  const auto key = make_key(0x42);

  // Same key with different timestamps should be allowed
  EXPECT_FALSE(cache.mark_and_check(1000, key));
  EXPECT_FALSE(cache.mark_and_check(2000, key));
  EXPECT_FALSE(cache.mark_and_check(3000, key));

  // But replays should still be detected
  EXPECT_TRUE(cache.mark_and_check(1000, key));
  EXPECT_TRUE(cache.mark_and_check(2000, key));
  EXPECT_TRUE(cache.mark_and_check(3000, key));
}

TEST_F(HandshakeReplayCacheTest, EvictsLRUWhenAtCapacity) {
  // Use longer time window to prevent auto-cleanup during test
  HandshakeReplayCache cache(3, std::chrono::milliseconds(100000));  // Small capacity
  const auto key1 = make_key(0x01);
  const auto key2 = make_key(0x02);
  const auto key3 = make_key(0x03);
  const auto key4 = make_key(0x04);

  // Fill cache to capacity
  EXPECT_FALSE(cache.mark_and_check(1000, key1));
  EXPECT_FALSE(cache.mark_and_check(2000, key2));
  EXPECT_FALSE(cache.mark_and_check(3000, key3));
  EXPECT_EQ(cache.size(), 3);

  // Add fourth entry - should evict key1 (least recently used)
  EXPECT_FALSE(cache.mark_and_check(4000, key4));
  EXPECT_EQ(cache.size(), 3);

  // Others should still be there (check these BEFORE key1 to avoid cache modification)
  EXPECT_TRUE(cache.mark_and_check(2000, key2));
  EXPECT_TRUE(cache.mark_and_check(3000, key3));
  EXPECT_TRUE(cache.mark_and_check(4000, key4));

  // key1 should have been evicted - will not detect as replay
  EXPECT_FALSE(cache.mark_and_check(1000, key1));
}

TEST_F(HandshakeReplayCacheTest, LRUOrderingUpdatedOnAccess) {
  HandshakeReplayCache cache(3);
  const auto key1 = make_key(0x01);
  const auto key2 = make_key(0x02);
  const auto key3 = make_key(0x03);
  const auto key4 = make_key(0x04);

  // Fill cache: key1, key2, key3 (key1 is LRU)
  EXPECT_FALSE(cache.mark_and_check(1000, key1));
  EXPECT_FALSE(cache.mark_and_check(2000, key2));
  EXPECT_FALSE(cache.mark_and_check(3000, key3));

  // Access key1 (moves it to MRU)
  EXPECT_TRUE(cache.mark_and_check(1000, key1));

  // Add key4 - should evict key2 (now LRU), not key1
  EXPECT_FALSE(cache.mark_and_check(4000, key4));

  // key1, key3, key4 should still be in cache
  EXPECT_TRUE(cache.mark_and_check(1000, key1));
  EXPECT_TRUE(cache.mark_and_check(3000, key3));
  EXPECT_TRUE(cache.mark_and_check(4000, key4));

  // key2 should have been evicted
  EXPECT_FALSE(cache.mark_and_check(2000, key2));
}

TEST_F(HandshakeReplayCacheTest, CleansUpExpiredEntries) {
  const auto time_window = std::chrono::milliseconds(1000);
  HandshakeReplayCache cache(100, time_window);
  const auto key1 = make_key(0x01);
  const auto key2 = make_key(0x02);
  const auto key3 = make_key(0x03);

  // Add entries at different timestamps
  EXPECT_FALSE(cache.mark_and_check(1000, key1));
  EXPECT_FALSE(cache.mark_and_check(1500, key2));
  EXPECT_FALSE(cache.mark_and_check(2000, key3));
  EXPECT_EQ(cache.size(), 3);

  // Cleanup with current_time = 3100
  // Cutoff = 3100 - 1000 = 2100
  // key1 (1000 < 2100): remove
  // key2 (1500 < 2100): remove
  // key3 (2000 < 2100): remove (2000 is also < 2100!)
  // All entries should be removed
  const auto removed = cache.cleanup_expired(3100);
  EXPECT_EQ(removed, 3);
  EXPECT_EQ(cache.size(), 0);

  // All keys should not be detected (were cleaned up)
  EXPECT_FALSE(cache.mark_and_check(1000, key1));
  EXPECT_FALSE(cache.mark_and_check(1500, key2));
  EXPECT_FALSE(cache.mark_and_check(2000, key3));
}

TEST_F(HandshakeReplayCacheTest, ClearRemovesAllEntries) {
  HandshakeReplayCache cache(100);
  const auto key1 = make_key(0x01);
  const auto key2 = make_key(0x02);

  EXPECT_FALSE(cache.mark_and_check(1000, key1));
  EXPECT_FALSE(cache.mark_and_check(2000, key2));
  EXPECT_EQ(cache.size(), 2);

  cache.clear();
  EXPECT_EQ(cache.size(), 0);

  // Entries should not be detected as replays after clear
  EXPECT_FALSE(cache.mark_and_check(1000, key1));
  EXPECT_FALSE(cache.mark_and_check(2000, key2));
}

TEST_F(HandshakeReplayCacheTest, ThreadSafety) {
  // Use large time window to prevent cleanup during test
  HandshakeReplayCache cache(2000, std::chrono::milliseconds(1000000));
  const auto key = make_key(0x42);

  // Multiple threads accessing with different timestamps
  constexpr int num_threads = 4;  // Reduced for faster test
  constexpr int iterations = 50;   // Reduced for faster test

  std::vector<std::thread> threads;
  threads.reserve(static_cast<std::size_t>(num_threads));
  std::atomic<int> total_replays{0};

  for (int t = 0; t < num_threads; ++t) {
    threads.emplace_back([&cache, &key, t, &total_replays]() {
      for (int i = 0; i < iterations; ++i) {
        // Each thread uses different timestamps
        const std::uint64_t ts = static_cast<std::uint64_t>(t) * 1000 + static_cast<std::uint64_t>(i);
        const bool is_replay = cache.mark_and_check(ts, key);
        if (is_replay) {
          total_replays.fetch_add(1, std::memory_order_relaxed);
        }
      }
    });
  }

  for (auto& thread : threads) {
    thread.join();
  }

  // All threads use different timestamps, so no replays should be detected
  EXPECT_EQ(total_replays.load(), 0);

  // Total entries should be num_threads * iterations
  EXPECT_EQ(cache.size(), num_threads * iterations);
}

TEST_F(HandshakeReplayCacheTest, ZeroCapacityThrows) {
  EXPECT_THROW(HandshakeReplayCache(0), std::invalid_argument);
}

TEST_F(HandshakeReplayCacheTest, CapacityAccessor) {
  HandshakeReplayCache cache(42);
  EXPECT_EQ(cache.capacity(), 42);
}

}  // namespace veil::handshake::test
