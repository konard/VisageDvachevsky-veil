#include <gtest/gtest.h>

#include <chrono>

#include "tun/mtu_discovery.h"

namespace veil::tun::test {

class PmtuDiscoveryTest : public ::testing::Test {
 protected:
  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;

  void SetUp() override {
    current_time_ = Clock::now();
    config_.initial_mtu = 1400;
    config_.min_mtu = 576;
    config_.max_mtu = 1500;
    config_.probe_interval = std::chrono::seconds(60);
    config_.max_probes = 3;
  }

  TimePoint now() { return current_time_; }

  void advance_time(std::chrono::seconds seconds) { current_time_ += seconds; }

  TimePoint current_time_;
  PmtuConfig config_;
};

TEST_F(PmtuDiscoveryTest, InitialMtu) {
  PmtuDiscovery pmtu(config_, [this]() { return now(); });

  // New peer should get initial MTU.
  EXPECT_EQ(pmtu.get_mtu("peer1"), config_.initial_mtu);
}

TEST_F(PmtuDiscoveryTest, SetMtu) {
  PmtuDiscovery pmtu(config_, [this]() { return now(); });

  pmtu.set_mtu("peer1", 1200);
  EXPECT_EQ(pmtu.get_mtu("peer1"), 1200);

  // Setting MTU below minimum should clamp.
  pmtu.set_mtu("peer1", 400);
  EXPECT_EQ(pmtu.get_mtu("peer1"), config_.min_mtu);

  // Setting MTU above maximum should clamp.
  pmtu.set_mtu("peer1", 9000);
  EXPECT_EQ(pmtu.get_mtu("peer1"), config_.max_mtu);
}

TEST_F(PmtuDiscoveryTest, FragmentationNeededWithMtu) {
  PmtuDiscovery pmtu(config_, [this]() { return now(); });

  // Start with default.
  EXPECT_EQ(pmtu.get_mtu("peer1"), 1400);

  // Receive ICMP with next-hop MTU.
  pmtu.handle_fragmentation_needed("peer1", 1200);

  // Should decrease by overhead.
  EXPECT_LT(pmtu.get_mtu("peer1"), 1200);
}

TEST_F(PmtuDiscoveryTest, FragmentationNeededWithoutMtu) {
  PmtuDiscovery pmtu(config_, [this]() { return now(); });

  // Start with default.
  EXPECT_EQ(pmtu.get_mtu("peer1"), 1400);

  // Receive ICMP without MTU hint.
  pmtu.handle_fragmentation_needed("peer1", 0);

  // Should decrease by ~20%.
  int expected = (1400 * 4) / 5;
  EXPECT_LE(pmtu.get_mtu("peer1"), expected);
}

TEST_F(PmtuDiscoveryTest, ProbeSuccess) {
  PmtuDiscovery pmtu(config_, [this]() { return now(); });

  // Set a lower MTU first.
  pmtu.set_mtu("peer1", 1200);
  EXPECT_EQ(pmtu.get_mtu("peer1"), 1200);

  // Successful probe at larger size.
  pmtu.handle_probe_success("peer1", 1350);

  // MTU should not increase from probe_success without probing flag.
  // The probe must be initiated first.
  EXPECT_EQ(pmtu.get_mtu("peer1"), 1200);
}

TEST_F(PmtuDiscoveryTest, ShouldProbeIncrease) {
  PmtuDiscovery pmtu(config_, [this]() { return now(); });

  pmtu.set_mtu("peer1", 1200);

  // Should not probe immediately.
  EXPECT_FALSE(pmtu.should_probe_increase("peer1"));

  // Advance time past probe interval.
  advance_time(std::chrono::seconds(61));

  // Now should probe.
  EXPECT_TRUE(pmtu.should_probe_increase("peer1"));
}

TEST_F(PmtuDiscoveryTest, ShouldNotProbeAtMaxMtu) {
  PmtuDiscovery pmtu(config_, [this]() { return now(); });

  pmtu.set_mtu("peer1", config_.max_mtu);
  advance_time(std::chrono::seconds(61));

  // Should not probe when at max MTU.
  EXPECT_FALSE(pmtu.should_probe_increase("peer1"));
}

TEST_F(PmtuDiscoveryTest, GetNextProbeSize) {
  PmtuDiscovery pmtu(config_, [this]() { return now(); });

  pmtu.set_mtu("peer1", 1200);

  // Next probe should be ~10% larger.
  int next_size = pmtu.get_next_probe_size("peer1");
  EXPECT_GT(next_size, 1200);
  EXPECT_LE(next_size, config_.max_mtu);
}

TEST_F(PmtuDiscoveryTest, PayloadSize) {
  PmtuDiscovery pmtu(config_, [this]() { return now(); });

  // Payload size should be MTU minus overhead.
  int mtu = pmtu.get_mtu("peer1");
  int payload = pmtu.get_payload_size("peer1");
  EXPECT_EQ(payload, mtu - kVeilOverhead);
}

TEST_F(PmtuDiscoveryTest, Reset) {
  PmtuDiscovery pmtu(config_, [this]() { return now(); });

  pmtu.set_mtu("peer1", 1200);
  EXPECT_EQ(pmtu.get_mtu("peer1"), 1200);

  pmtu.reset("peer1");
  EXPECT_EQ(pmtu.get_mtu("peer1"), config_.initial_mtu);
}

TEST_F(PmtuDiscoveryTest, RemovePeer) {
  PmtuDiscovery pmtu(config_, [this]() { return now(); });

  pmtu.set_mtu("peer1", 1200);
  EXPECT_EQ(pmtu.get_mtu("peer1"), 1200);

  pmtu.remove_peer("peer1");

  // After removal, should get initial MTU again.
  EXPECT_EQ(pmtu.get_mtu("peer1"), config_.initial_mtu);
}

TEST_F(PmtuDiscoveryTest, MtuChangeCallback) {
  PmtuDiscovery pmtu(config_, [this]() { return now(); });

  std::string callback_peer;
  int callback_old_mtu = 0;
  int callback_new_mtu = 0;

  pmtu.set_mtu_change_callback([&](const std::string& peer, int old_mtu, int new_mtu) {
    callback_peer = peer;
    callback_old_mtu = old_mtu;
    callback_new_mtu = new_mtu;
  });

  // Changing MTU should trigger callback.
  pmtu.set_mtu("peer1", 1200);

  EXPECT_EQ(callback_peer, "peer1");
  EXPECT_EQ(callback_old_mtu, config_.initial_mtu);
  EXPECT_EQ(callback_new_mtu, 1200);
}

TEST_F(PmtuDiscoveryTest, MultiplePeers) {
  PmtuDiscovery pmtu(config_, [this]() { return now(); });

  pmtu.set_mtu("peer1", 1200);
  pmtu.set_mtu("peer2", 1300);
  pmtu.set_mtu("peer3", 1400);

  EXPECT_EQ(pmtu.get_mtu("peer1"), 1200);
  EXPECT_EQ(pmtu.get_mtu("peer2"), 1300);
  EXPECT_EQ(pmtu.get_mtu("peer3"), 1400);
}

}  // namespace veil::tun::test
