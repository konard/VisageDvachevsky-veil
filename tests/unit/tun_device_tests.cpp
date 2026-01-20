#include <gtest/gtest.h>

#include <system_error>

#include "tun/tun_device.h"

namespace veil::tun::test {

class TunDeviceTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Skip tests that require root privileges.
    if (getuid() != 0) {
      GTEST_SKIP() << "TUN device tests require root privileges";
    }
  }
};

TEST_F(TunDeviceTest, DefaultConstructor) {
  TunDevice device;
  EXPECT_FALSE(device.is_open());
  EXPECT_EQ(device.fd(), -1);
  EXPECT_TRUE(device.device_name().empty());
}

TEST_F(TunDeviceTest, OpenWithConfig) {
  TunConfig config;
  config.device_name = "veil_test0";
  config.ip_address = "10.99.0.1";
  config.netmask = "255.255.255.0";
  config.mtu = 1400;
  config.bring_up = true;

  TunDevice device;
  std::error_code ec;

  bool opened = device.open(config, ec);
  if (!opened) {
    // May fail due to permissions or existing device.
    GTEST_SKIP() << "Failed to open TUN device: " << ec.message();
  }

  EXPECT_TRUE(device.is_open());
  EXPECT_GE(device.fd(), 0);
  EXPECT_EQ(device.device_name(), "veil_test0");

  device.close();
  EXPECT_FALSE(device.is_open());
  EXPECT_EQ(device.fd(), -1);
}

TEST_F(TunDeviceTest, MoveConstructor) {
  TunConfig config;
  config.device_name = "veil_test1";
  config.ip_address = "10.99.1.1";
  config.mtu = 1400;

  TunDevice device1;
  std::error_code ec;

  if (!device1.open(config, ec)) {
    GTEST_SKIP() << "Failed to open TUN device: " << ec.message();
  }

  int original_fd = device1.fd();
  std::string original_name = device1.device_name();

  TunDevice device2(std::move(device1));

  // device1 should be invalidated.
  // NOLINTBEGIN(bugprone-use-after-move) - intentionally testing moved-from state
  EXPECT_FALSE(device1.is_open());
  EXPECT_EQ(device1.fd(), -1);
  // NOLINTEND(bugprone-use-after-move)

  // device2 should have the original values.
  EXPECT_TRUE(device2.is_open());
  EXPECT_EQ(device2.fd(), original_fd);
  EXPECT_EQ(device2.device_name(), original_name);
}

TEST_F(TunDeviceTest, MoveAssignment) {
  TunConfig config1;
  config1.device_name = "veil_test2";
  config1.ip_address = "10.99.2.1";

  TunConfig config2;
  config2.device_name = "veil_test3";
  config2.ip_address = "10.99.3.1";

  TunDevice device1;
  TunDevice device2;
  std::error_code ec;

  if (!device1.open(config1, ec)) {
    GTEST_SKIP() << "Failed to open first TUN device: " << ec.message();
  }

  if (!device2.open(config2, ec)) {
    device1.close();
    GTEST_SKIP() << "Failed to open second TUN device: " << ec.message();
  }

  int fd1 = device1.fd();
  device2 = std::move(device1);

  // device1 should be invalidated.
  // NOLINTBEGIN(bugprone-use-after-move) - intentionally testing moved-from state
  EXPECT_FALSE(device1.is_open());
  // NOLINTEND(bugprone-use-after-move)

  // device2 should have device1's fd.
  EXPECT_TRUE(device2.is_open());
  EXPECT_EQ(device2.fd(), fd1);
}

TEST_F(TunDeviceTest, StatsInitialization) {
  TunDevice device;
  const auto& stats = device.stats();

  EXPECT_EQ(stats.packets_read, 0u);
  EXPECT_EQ(stats.packets_written, 0u);
  EXPECT_EQ(stats.bytes_read, 0u);
  EXPECT_EQ(stats.bytes_written, 0u);
  EXPECT_EQ(stats.read_errors, 0u);
  EXPECT_EQ(stats.write_errors, 0u);
}

// Tests that don't require root privileges.
class TunDeviceUnitTest : public ::testing::Test {};

TEST_F(TunDeviceUnitTest, ConfigDefaults) {
  TunConfig config;

  EXPECT_TRUE(config.device_name.empty());
  EXPECT_TRUE(config.ip_address.empty());
  EXPECT_EQ(config.netmask, "255.255.255.0");
  EXPECT_EQ(config.mtu, 1400);
  EXPECT_FALSE(config.packet_info);
  EXPECT_TRUE(config.bring_up);
}

TEST_F(TunDeviceUnitTest, OpenWithoutRoot) {
  TunConfig config;
  config.device_name = "test0";
  config.ip_address = "10.99.0.1";

  TunDevice device;
  std::error_code ec;

  // This should fail without root.
  bool opened = device.open(config, ec);
  if (getuid() != 0) {
    EXPECT_FALSE(opened);
    EXPECT_TRUE(ec);  // Error code should be set.
  }
}

}  // namespace veil::tun::test
