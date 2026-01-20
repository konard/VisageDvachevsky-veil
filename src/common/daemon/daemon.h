#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <system_error>

namespace veil::daemon {

// Configuration for daemon mode.
struct DaemonConfig {
  // Working directory for the daemon (empty = stay in current dir).
  std::string working_dir;
  // PID file path (empty = no PID file).
  std::string pid_file;
  // User to run as (empty = don't change).
  std::string user;
  // Group to run as (empty = don't change).
  std::string group;
  // Close standard file descriptors.
  bool close_stdio{true};
  // Redirect stdio to /dev/null.
  bool redirect_stdio{true};
  // Create a new session (setsid).
  bool new_session{true};
};

// Daemonize the current process.
// Returns true if daemonization succeeded.
// After successful return, the caller is the daemon process.
bool daemonize(const DaemonConfig& config, std::error_code& ec);

// Write PID file.
bool write_pid_file(const std::string& path, std::error_code& ec);

// Remove PID file.
bool remove_pid_file(const std::string& path, std::error_code& ec);

// Read PID from file.
std::optional<pid_t> read_pid_file(const std::string& path, std::error_code& ec);

// Check if a process with given PID is running.
bool is_process_running(pid_t pid);

// Check if another instance is already running (using PID file).
bool is_already_running(const std::string& pid_file, std::error_code& ec);

// Drop privileges to specified user/group.
bool drop_privileges(const std::string& user, const std::string& group, std::error_code& ec);

// Get current process PID.
pid_t get_pid();

// RAII PID file manager.
class PidFile {
 public:
  explicit PidFile(std::string path);
  ~PidFile();

  // Non-copyable, non-movable.
  PidFile(const PidFile&) = delete;
  PidFile& operator=(const PidFile&) = delete;
  PidFile(PidFile&&) = delete;
  PidFile& operator=(PidFile&&) = delete;

  // Create the PID file.
  bool create(std::error_code& ec);

  // Check if creation was successful.
  bool is_valid() const { return valid_; }

  // Get the path.
  const std::string& path() const { return path_; }

 private:
  std::string path_;
  bool valid_{false};
};

}  // namespace veil::daemon
