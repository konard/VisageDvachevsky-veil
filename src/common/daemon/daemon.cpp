#include "common/daemon/daemon.h"

#include <csignal>
#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <system_error>

#include "common/logging/logger.h"

namespace {
std::error_code last_error() { return std::error_code(errno, std::generic_category()); }
}  // namespace

namespace veil::daemon {

bool daemonize(const DaemonConfig& config, std::error_code& ec) {
  // First fork.
  pid_t pid = fork();
  if (pid < 0) {
    ec = last_error();
    LOG_ERROR("First fork failed: {}", ec.message());
    return false;
  }
  if (pid > 0) {
    // Parent process exits.
    _exit(0);
  }

  // Create new session.
  if (config.new_session) {
    if (setsid() < 0) {
      ec = last_error();
      LOG_ERROR("setsid failed: {}", ec.message());
      return false;
    }
  }

  // Second fork to prevent acquiring a controlling terminal.
  pid = fork();
  if (pid < 0) {
    ec = last_error();
    LOG_ERROR("Second fork failed: {}", ec.message());
    return false;
  }
  if (pid > 0) {
    _exit(0);
  }

  // Set file creation mask.
  umask(0);

  // Change working directory.
  if (!config.working_dir.empty()) {
    if (chdir(config.working_dir.c_str()) != 0) {
      ec = last_error();
      LOG_ERROR("Failed to change directory to {}: {}", config.working_dir, ec.message());
      return false;
    }
  }

  // Close and redirect standard file descriptors.
  if (config.close_stdio || config.redirect_stdio) {
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    if (config.redirect_stdio) {
      // Redirect to /dev/null.
      int null_fd = open("/dev/null", O_RDWR);
      if (null_fd >= 0) {
        dup2(null_fd, STDIN_FILENO);
        dup2(null_fd, STDOUT_FILENO);
        dup2(null_fd, STDERR_FILENO);
        if (null_fd > STDERR_FILENO) {
          close(null_fd);
        }
      }
    }
  }

  // Write PID file.
  if (!config.pid_file.empty()) {
    if (!write_pid_file(config.pid_file, ec)) {
      LOG_ERROR("Failed to write PID file: {}", ec.message());
      return false;
    }
  }

  // Drop privileges.
  if (!config.user.empty() || !config.group.empty()) {
    if (!drop_privileges(config.user, config.group, ec)) {
      LOG_ERROR("Failed to drop privileges: {}", ec.message());
      return false;
    }
  }

  LOG_INFO("Daemonized successfully, PID: {}", getpid());
  return true;
}

bool write_pid_file(const std::string& path, std::error_code& ec) {
  std::ofstream file(path);
  if (!file) {
    ec = last_error();
    return false;
  }

  file << getpid() << '\n';
  if (!file) {
    ec = last_error();
    return false;
  }

  LOG_DEBUG("PID file written: {}", path);
  return true;
}

bool remove_pid_file(const std::string& path, std::error_code& ec) {
  if (unlink(path.c_str()) != 0) {
    if (errno != ENOENT) {  // Ignore if file doesn't exist.
      ec = last_error();
      return false;
    }
  }
  return true;
}

std::optional<pid_t> read_pid_file(const std::string& path, std::error_code& ec) {
  std::ifstream file(path);
  if (!file) {
    ec = last_error();
    return std::nullopt;
  }

  pid_t pid = 0;
  file >> pid;
  if (!file) {
    ec = std::make_error_code(std::errc::invalid_argument);
    return std::nullopt;
  }

  return pid;
}

bool is_process_running(pid_t pid) {
  // Send signal 0 to check if process exists.
  return kill(pid, 0) == 0 || errno != ESRCH;
}

bool is_already_running(const std::string& pid_file, std::error_code& ec) {
  auto pid = read_pid_file(pid_file, ec);
  if (!pid) {
    // No PID file or can't read it.
    ec.clear();
    return false;
  }

  return is_process_running(*pid);
}

bool drop_privileges(const std::string& user, const std::string& group, std::error_code& ec) {
  // Set group first (must be done before changing user).
  if (!group.empty()) {
    struct group* grp = getgrnam(group.c_str());
    if (grp == nullptr) {
      ec = last_error();
      LOG_ERROR("Group not found: {}", group);
      return false;
    }

    if (setgid(grp->gr_gid) != 0) {
      ec = last_error();
      LOG_ERROR("Failed to set GID to {}: {}", grp->gr_gid, ec.message());
      return false;
    }

    // Also set supplementary groups.
    if (initgroups(user.empty() ? "nobody" : user.c_str(), grp->gr_gid) != 0) {
      ec = last_error();
      LOG_WARN("Failed to set supplementary groups: {}", ec.message());
      // Don't fail, this is not critical.
    }
  }

  // Set user.
  if (!user.empty()) {
    struct passwd* pwd = getpwnam(user.c_str());
    if (pwd == nullptr) {
      ec = last_error();
      LOG_ERROR("User not found: {}", user);
      return false;
    }

    if (setuid(pwd->pw_uid) != 0) {
      ec = last_error();
      LOG_ERROR("Failed to set UID to {}: {}", pwd->pw_uid, ec.message());
      return false;
    }
  }

  LOG_INFO("Dropped privileges to {}:{}", user.empty() ? "(unchanged)" : user,
           group.empty() ? "(unchanged)" : group);
  return true;
}

pid_t get_pid() { return getpid(); }

// PidFile implementation.

PidFile::PidFile(std::string path) : path_(std::move(path)) {}

PidFile::~PidFile() {
  if (valid_) {
    std::error_code ec;
    remove_pid_file(path_, ec);
  }
}

bool PidFile::create(std::error_code& ec) {
  if (write_pid_file(path_, ec)) {
    valid_ = true;
    return true;
  }
  return false;
}

}  // namespace veil::daemon
