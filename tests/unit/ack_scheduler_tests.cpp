#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>

#include "transport/mux/ack_scheduler.h"

namespace veil::mux::tests {

using namespace std::chrono_literals;

class AckSchedulerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    now_ = std::chrono::steady_clock::now();
    config_.max_ack_delay = 50ms;
    config_.ack_every_n_packets = 2;
    config_.enable_coalescing = true;
    config_.max_pending_acks = 8;
    config_.immediate_ack_on_gap = true;
    config_.immediate_ack_on_fin = true;
  }

  std::chrono::steady_clock::time_point now_;
  AckSchedulerConfig config_;
};

TEST_F(AckSchedulerTest, ImmediateAckAfterNPackets) {
  AckScheduler scheduler(config_, [this]() { return now_; });

  // First packet: should not trigger immediate ACK.
  bool immediate1 = scheduler.on_packet_received(0, 1, false);
  EXPECT_FALSE(immediate1);

  // Second packet: should trigger immediate ACK (ack_every_n_packets = 2).
  bool immediate2 = scheduler.on_packet_received(0, 2, false);
  EXPECT_TRUE(immediate2);
}

TEST_F(AckSchedulerTest, ImmediateAckOnFin) {
  AckScheduler scheduler(config_, [this]() { return now_; });

  // FIN packet should trigger immediate ACK.
  bool immediate = scheduler.on_packet_received(0, 1, true);
  EXPECT_TRUE(immediate);
}

TEST_F(AckSchedulerTest, ImmediateAckOnGap) {
  AckScheduler scheduler(config_, [this]() { return now_; });

  // First packet.
  scheduler.on_packet_received(0, 1, false);

  // Packet with gap (skip sequence 2).
  bool immediate = scheduler.on_packet_received(0, 3, false);
  EXPECT_TRUE(immediate);

  EXPECT_EQ(scheduler.stats().gaps_detected, 1U);
}

TEST_F(AckSchedulerTest, DelayedAck) {
  AckScheduler scheduler(config_, [this]() { return now_; });

  // First packet.
  bool immediate = scheduler.on_packet_received(0, 1, false);
  EXPECT_FALSE(immediate);

  // Check timer: should not be due yet.
  auto due = scheduler.check_ack_timer();
  EXPECT_FALSE(due.has_value());

  // Advance time past delay.
  now_ += 60ms;
  due = scheduler.check_ack_timer();
  EXPECT_TRUE(due.has_value());
  EXPECT_EQ(*due, 0U);
}

TEST_F(AckSchedulerTest, GetPendingAck) {
  AckScheduler scheduler(config_, [this]() { return now_; });

  // Receive packets.
  scheduler.on_packet_received(0, 1, false);
  scheduler.on_packet_received(0, 2, false);

  // Get pending ACK.
  auto ack = scheduler.get_pending_ack(0);
  ASSERT_TRUE(ack.has_value());
  EXPECT_EQ(ack->stream_id, 0U);
  EXPECT_EQ(ack->ack, 2U);
}

TEST_F(AckSchedulerTest, AckSentClearsState) {
  AckScheduler scheduler(config_, [this]() { return now_; });

  scheduler.on_packet_received(0, 1, false);
  scheduler.on_packet_received(0, 2, false);

  // Mark ACK as sent.
  scheduler.ack_sent(0);

  // Should no longer have pending ACK.
  auto ack = scheduler.get_pending_ack(0);
  EXPECT_FALSE(ack.has_value());

  EXPECT_EQ(scheduler.stats().acks_sent, 1U);
}

TEST_F(AckSchedulerTest, AckCoalescing) {
  AckScheduler scheduler(config_, [this]() { return now_; });

  // Receive multiple packets.
  scheduler.on_packet_received(0, 1, false);
  scheduler.on_packet_received(0, 2, false);
  scheduler.on_packet_received(0, 3, false);
  scheduler.on_packet_received(0, 4, false);

  // Mark ACK as sent (4 packets coalesced into 1 ACK).
  scheduler.ack_sent(0);

  // Should count coalesced ACKs.
  EXPECT_EQ(scheduler.stats().acks_coalesced, 3U);  // 4 packets - 1 ack = 3 coalesced
}

TEST_F(AckSchedulerTest, TimeUntilNextAck) {
  AckScheduler scheduler(config_, [this]() { return now_; });

  // No pending ACKs.
  auto time = scheduler.time_until_next_ack();
  EXPECT_FALSE(time.has_value());

  // Receive packet.
  scheduler.on_packet_received(0, 1, false);

  // Should have time until next ACK.
  time = scheduler.time_until_next_ack();
  ASSERT_TRUE(time.has_value());
  EXPECT_GT(*time, 0ms);
  EXPECT_LE(*time, 50ms);

  // Advance time.
  now_ += 30ms;
  time = scheduler.time_until_next_ack();
  ASSERT_TRUE(time.has_value());
  EXPECT_LT(*time, 25ms);
}

TEST_F(AckSchedulerTest, MultipleStreams) {
  AckScheduler scheduler(config_, [this]() { return now_; });

  // Receive packets on different streams.
  scheduler.on_packet_received(0, 1, false);
  scheduler.on_packet_received(1, 1, false);
  scheduler.on_packet_received(2, 1, false);

  // Each stream should have pending ACK.
  EXPECT_TRUE(scheduler.get_pending_ack(0).has_value());
  EXPECT_TRUE(scheduler.get_pending_ack(1).has_value());
  EXPECT_TRUE(scheduler.get_pending_ack(2).has_value());

  // Reset one stream.
  scheduler.reset_stream(1);
  EXPECT_TRUE(scheduler.get_pending_ack(0).has_value());
  EXPECT_FALSE(scheduler.get_pending_ack(1).has_value());
  EXPECT_TRUE(scheduler.get_pending_ack(2).has_value());
}

TEST_F(AckSchedulerTest, DelayedAckStats) {
  AckScheduler scheduler(config_, [this]() { return now_; });

  // First packet: delayed.
  scheduler.on_packet_received(0, 1, false);
  EXPECT_EQ(scheduler.stats().acks_delayed, 1U);
  EXPECT_EQ(scheduler.stats().acks_immediate, 0U);

  // Second packet: immediate.
  scheduler.on_packet_received(0, 2, false);
  EXPECT_EQ(scheduler.stats().acks_delayed, 1U);
  EXPECT_EQ(scheduler.stats().acks_immediate, 1U);
}

}  // namespace veil::mux::tests
