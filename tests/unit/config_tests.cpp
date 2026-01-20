#include <gtest/gtest.h>

#include <string>

#include "common/config/app_config.h"

namespace veil::tests {

TEST(ConfigTests, ParseDefaultValues) {
  const char* argv[] = {"veil", nullptr};
  auto config = config::parse_arguments(1, const_cast<char**>(argv));
  EXPECT_EQ(config.config_path, "");
  EXPECT_EQ(config.log_level, logging::LogLevel::info);
  EXPECT_TRUE(config.log_to_stdout);
}

TEST(ConfigTests, ParseOptions) {
  const char* argv[] = {"veil", "-c", "/tmp/veil.conf", "--log-level", "debug", "--log-to-stderr", nullptr};
  auto config = config::parse_arguments(6, const_cast<char**>(argv));
  EXPECT_EQ(config.config_path, "/tmp/veil.conf");
  EXPECT_EQ(config.log_level, logging::LogLevel::debug);
  EXPECT_FALSE(config.log_to_stdout);
}

}  // namespace veil::tests
