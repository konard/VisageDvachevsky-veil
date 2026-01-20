#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <vector>

#include "transport/mux/retransmit_buffer.h"

namespace veil::tests {

using namespace std::chrono_literals;

TEST(RetransmitBufferTests, InsertAndAcknowledge) {
  std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
  auto now_fn = [&]() { return now; };

  mux::RetransmitBuffer buffer({}, now_fn);

  std::vector<std::uint8_t> data{1, 2, 3, 4};
  EXPECT_TRUE(buffer.insert(1, data));
  EXPECT_EQ(buffer.pending_count(), 1U);
  EXPECT_EQ(buffer.buffered_bytes(), 4U);

  // Advance time and acknowledge
  now += 50ms;
  EXPECT_TRUE(buffer.acknowledge(1));
  EXPECT_EQ(buffer.pending_count(), 0U);
  EXPECT_EQ(buffer.buffered_bytes(), 0U);
  EXPECT_EQ(buffer.stats().packets_acked, 1U);
}

TEST(RetransmitBufferTests, AcknowledgeCumulative) {
  std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
  auto now_fn = [&]() { return now; };

  mux::RetransmitBuffer buffer({}, now_fn);

  buffer.insert(1, {1});
  buffer.insert(2, {2, 3});
  buffer.insert(3, {4, 5, 6});
  buffer.insert(5, {7});  // Gap at 4
  EXPECT_EQ(buffer.pending_count(), 4U);

  now += 50ms;
  buffer.acknowledge_cumulative(3);
  EXPECT_EQ(buffer.pending_count(), 1U);
  EXPECT_EQ(buffer.stats().packets_acked, 3U);
  EXPECT_FALSE(buffer.acknowledge(1));  // Already acked
  EXPECT_TRUE(buffer.acknowledge(5));   // Still pending
}

TEST(RetransmitBufferTests, RetransmitTimeout) {
  std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
  auto now_fn = [&]() { return now; };

  mux::RetransmitConfig config;
  config.initial_rtt = 100ms;
  mux::RetransmitBuffer buffer(config, now_fn);

  buffer.insert(1, {1, 2, 3});

  // Just after insertion, no retransmit needed
  auto to_retransmit = buffer.get_packets_to_retransmit();
  EXPECT_TRUE(to_retransmit.empty());

  // Advance past initial RTO
  now += 101ms;
  to_retransmit = buffer.get_packets_to_retransmit();
  EXPECT_EQ(to_retransmit.size(), 1U);
  EXPECT_EQ(to_retransmit[0]->sequence, 1U);

  // Mark as retransmitted
  EXPECT_TRUE(buffer.mark_retransmitted(1));
  EXPECT_EQ(buffer.stats().packets_retransmitted, 1U);

  // Should not need immediate retransmit again
  to_retransmit = buffer.get_packets_to_retransmit();
  EXPECT_TRUE(to_retransmit.empty());
}

TEST(RetransmitBufferTests, ExponentialBackoff) {
  std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
  auto now_fn = [&]() { return now; };

  mux::RetransmitConfig config;
  config.initial_rtt = 100ms;
  config.backoff_factor = 2.0;
  config.max_retries = 3;
  mux::RetransmitBuffer buffer(config, now_fn);

  buffer.insert(1, {1});

  // First retransmit at ~100ms
  now += 101ms;
  auto pkts = buffer.get_packets_to_retransmit();
  EXPECT_EQ(pkts.size(), 1U);
  EXPECT_TRUE(buffer.mark_retransmitted(1));

  // Second retransmit should be at ~200ms (backoff * 2)
  now += 199ms;
  pkts = buffer.get_packets_to_retransmit();
  EXPECT_TRUE(pkts.empty());  // Not yet

  now += 10ms;
  pkts = buffer.get_packets_to_retransmit();
  EXPECT_EQ(pkts.size(), 1U);
  EXPECT_TRUE(buffer.mark_retransmitted(1));

  // Third retransmit at ~400ms
  now += 401ms;
  pkts = buffer.get_packets_to_retransmit();
  EXPECT_EQ(pkts.size(), 1U);
  EXPECT_TRUE(buffer.mark_retransmitted(1));

  // Fourth would exceed max_retries
  now += 801ms;
  pkts = buffer.get_packets_to_retransmit();
  EXPECT_EQ(pkts.size(), 1U);
  EXPECT_FALSE(buffer.mark_retransmitted(1));  // Exceeded max retries
}

TEST(RetransmitBufferTests, BufferLimitEnforced) {
  std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
  auto now_fn = [&]() { return now; };

  mux::RetransmitConfig config;
  config.max_buffer_bytes = 10;
  // Use kNewest policy so new inserts are rejected when buffer is full.
  config.drop_policy = mux::DropPolicy::kNewest;
  mux::RetransmitBuffer buffer(config, now_fn);

  EXPECT_TRUE(buffer.insert(1, {1, 2, 3, 4}));  // 4 bytes
  EXPECT_TRUE(buffer.insert(2, {5, 6, 7, 8}));  // 4 bytes -> 8 total
  EXPECT_FALSE(buffer.insert(3, {9, 10, 11})); // Would exceed 10 bytes
  EXPECT_TRUE(buffer.insert(3, {9, 10}));       // 2 bytes -> 10 total
  EXPECT_FALSE(buffer.insert(4, {11}));         // Buffer full

  EXPECT_EQ(buffer.buffered_bytes(), 10U);
  EXPECT_FALSE(buffer.has_capacity(1));

  buffer.acknowledge(1);
  EXPECT_EQ(buffer.buffered_bytes(), 6U);
  EXPECT_TRUE(buffer.has_capacity(4));
}

TEST(RetransmitBufferTests, RttEstimation) {
  std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
  auto now_fn = [&]() { return now; };

  mux::RetransmitConfig config;
  config.initial_rtt = 100ms;
  mux::RetransmitBuffer buffer(config, now_fn);

  // First packet with 80ms RTT
  buffer.insert(1, {1});
  now += 80ms;
  buffer.acknowledge(1);
  EXPECT_EQ(buffer.estimated_rtt(), 80ms);

  // Second packet with 120ms RTT - should smooth
  buffer.insert(2, {2});
  now += 120ms;
  buffer.acknowledge(2);
  // SRTT = (1-0.125)*80 + 0.125*120 = 70 + 15 = 85
  EXPECT_GE(buffer.estimated_rtt().count(), 80);
  EXPECT_LE(buffer.estimated_rtt().count(), 90);
}

TEST(RetransmitBufferTests, KarnsAlgorithm) {
  std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
  auto now_fn = [&]() { return now; };

  mux::RetransmitConfig config;
  config.initial_rtt = 100ms;
  mux::RetransmitBuffer buffer(config, now_fn);

  buffer.insert(1, {1});

  // Force retransmit
  now += 101ms;
  auto pkts = buffer.get_packets_to_retransmit();
  buffer.mark_retransmitted(1);

  // Acknowledge after retransmit - RTT should not be updated (Karn's)
  auto rtt_before = buffer.estimated_rtt();
  now += 50ms;
  buffer.acknowledge(1);
  EXPECT_EQ(buffer.estimated_rtt(), rtt_before);  // Unchanged
}

TEST(RetransmitBufferTests, DropPacket) {
  std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
  auto now_fn = [&]() { return now; };

  mux::RetransmitBuffer buffer({}, now_fn);

  buffer.insert(1, {1, 2, 3});
  buffer.insert(2, {4, 5});
  EXPECT_EQ(buffer.pending_count(), 2U);
  EXPECT_EQ(buffer.buffered_bytes(), 5U);

  buffer.drop_packet(1);
  EXPECT_EQ(buffer.pending_count(), 1U);
  EXPECT_EQ(buffer.buffered_bytes(), 2U);
  EXPECT_EQ(buffer.stats().packets_dropped, 1U);
}

TEST(RetransmitBufferTests, DuplicateInsertRejected) {
  std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
  auto now_fn = [&]() { return now; };

  mux::RetransmitBuffer buffer({}, now_fn);

  EXPECT_TRUE(buffer.insert(1, {1, 2, 3}));
  EXPECT_FALSE(buffer.insert(1, {4, 5, 6}));  // Duplicate
  EXPECT_EQ(buffer.pending_count(), 1U);
  EXPECT_EQ(buffer.buffered_bytes(), 3U);
}

TEST(RetransmitBufferTests, MinMaxRtoClamping) {
  std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
  auto now_fn = [&]() { return now; };

  mux::RetransmitConfig config;
  config.min_rto = 50ms;
  config.max_rto = 500ms;
  config.initial_rtt = 10ms;  // Very low
  mux::RetransmitBuffer buffer(config, now_fn);

  // With very low RTT, RTO should still be >= min_rto
  buffer.insert(1, {1});
  now += 10ms;
  buffer.acknowledge(1);
  EXPECT_GE(buffer.current_rto().count(), 50);

  // With very high RTT simulation, RTO should be capped at max_rto
  buffer.insert(2, {2});
  now += 10000ms;  // Very long delay
  buffer.acknowledge(2);
  EXPECT_LE(buffer.current_rto().count(), 500);
}

}  // namespace veil::tests
