#include <gtest/gtest.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <system_error>

#include "common/daemon/daemon.h"

namespace veil::daemon::test {

class DaemonTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Create a temporary directory for test files.
    test_dir_ = std::filesystem::temp_directory_path() / "veil_daemon_test";
    std::filesystem::create_directories(test_dir_);
    test_pid_file_ = test_dir_ / "test.pid";
  }

  void TearDown() override {
    // Clean up test files.
    std::error_code ec;
    std::filesystem::remove_all(test_dir_, ec);
  }

  std::filesystem::path test_dir_;
  std::filesystem::path test_pid_file_;
};

TEST_F(DaemonTest, WritePidFile) {
  std::error_code ec;

  EXPECT_TRUE(write_pid_file(test_pid_file_.string(), ec));
  EXPECT_FALSE(ec);

  // Verify file exists.
  EXPECT_TRUE(std::filesystem::exists(test_pid_file_));

  // Verify content.
  std::ifstream file(test_pid_file_);
  pid_t pid = 0;
  file >> pid;
  EXPECT_EQ(pid, getpid());
}

TEST_F(DaemonTest, ReadPidFile) {
  // Write a known PID.
  {
    std::ofstream file(test_pid_file_);
    file << 12345 << '\n';
  }

  std::error_code ec;
  auto result = read_pid_file(test_pid_file_.string(), ec);

  EXPECT_TRUE(result.has_value());
  EXPECT_EQ(*result, 12345);
}

TEST_F(DaemonTest, ReadNonexistentPidFile) {
  std::error_code ec;
  auto result = read_pid_file("/nonexistent/path/test.pid", ec);

  EXPECT_FALSE(result.has_value());
  EXPECT_TRUE(ec);
}

TEST_F(DaemonTest, RemovePidFile) {
  // Create the file first.
  std::error_code ec;
  EXPECT_TRUE(write_pid_file(test_pid_file_.string(), ec));
  EXPECT_TRUE(std::filesystem::exists(test_pid_file_));

  // Remove it.
  EXPECT_TRUE(remove_pid_file(test_pid_file_.string(), ec));
  EXPECT_FALSE(std::filesystem::exists(test_pid_file_));
}

TEST_F(DaemonTest, RemoveNonexistentPidFile) {
  std::error_code ec;
  // Removing a non-existent file should succeed.
  EXPECT_TRUE(remove_pid_file(test_pid_file_.string(), ec));
}

TEST_F(DaemonTest, IsProcessRunning) {
  // Current process should be running.
  EXPECT_TRUE(is_process_running(getpid()));

  // PID 1 (init/systemd) should be running.
  EXPECT_TRUE(is_process_running(1));

  // Very high PID unlikely to exist.
  EXPECT_FALSE(is_process_running(999999999));
}

TEST_F(DaemonTest, GetPid) { EXPECT_EQ(get_pid(), getpid()); }

TEST_F(DaemonTest, IsAlreadyRunningNotRunning) {
  std::error_code ec;

  // File doesn't exist - not running.
  EXPECT_FALSE(is_already_running(test_pid_file_.string(), ec));
}

TEST_F(DaemonTest, IsAlreadyRunningCurrentProcess) {
  // Write current process PID.
  std::error_code ec;
  EXPECT_TRUE(write_pid_file(test_pid_file_.string(), ec));

  // Should detect as running.
  EXPECT_TRUE(is_already_running(test_pid_file_.string(), ec));
}

TEST_F(DaemonTest, IsAlreadyRunningDeadProcess) {
  // Write a non-existent PID.
  {
    std::ofstream file(test_pid_file_);
    file << 999999999 << '\n';
  }

  std::error_code ec;
  // Should detect as not running.
  EXPECT_FALSE(is_already_running(test_pid_file_.string(), ec));
}

// PidFile RAII class tests.
class PidFileTest : public ::testing::Test {
 protected:
  void SetUp() override {
    test_dir_ = std::filesystem::temp_directory_path() / "veil_pidfile_test";
    std::filesystem::create_directories(test_dir_);
    test_pid_file_ = test_dir_ / "test.pid";
  }

  void TearDown() override {
    std::error_code ec;
    std::filesystem::remove_all(test_dir_, ec);
  }

  std::filesystem::path test_dir_;
  std::filesystem::path test_pid_file_;
};

TEST_F(PidFileTest, CreateAndDestroy) {
  {
    PidFile pid_file(test_pid_file_.string());
    std::error_code ec;

    EXPECT_TRUE(pid_file.create(ec));
    EXPECT_TRUE(pid_file.is_valid());
    EXPECT_EQ(pid_file.path(), test_pid_file_.string());
    EXPECT_TRUE(std::filesystem::exists(test_pid_file_));
  }

  // File should be removed when PidFile is destroyed.
  EXPECT_FALSE(std::filesystem::exists(test_pid_file_));
}

TEST_F(PidFileTest, CreateFailure) {
  // Try to create in non-existent directory.
  PidFile pid_file("/nonexistent/directory/test.pid");
  std::error_code ec;

  EXPECT_FALSE(pid_file.create(ec));
  EXPECT_FALSE(pid_file.is_valid());
  EXPECT_TRUE(ec);
}

// DaemonConfig tests.
TEST(DaemonConfigTest, Defaults) {
  DaemonConfig config;

  EXPECT_TRUE(config.working_dir.empty());
  EXPECT_TRUE(config.pid_file.empty());
  EXPECT_TRUE(config.user.empty());
  EXPECT_TRUE(config.group.empty());
  EXPECT_TRUE(config.close_stdio);
  EXPECT_TRUE(config.redirect_stdio);
  EXPECT_TRUE(config.new_session);
}

// Note: daemonize() and drop_privileges() are not tested here
// because they require root privileges and would exit the test process.

}  // namespace veil::daemon::test
