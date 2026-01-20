#pragma once

#include <atomic>
#include <csignal>
#include <functional>
#include <unordered_map>
#include <vector>

namespace veil::signal {

// Supported signals.
enum class Signal {
  kInterrupt = SIGINT,   // Ctrl+C.
  kTerminate = SIGTERM,  // kill command.
  kHangup = SIGHUP,      // Terminal hangup / config reload.
  kUser1 = SIGUSR1,      // Custom signal 1.
  kUser2 = SIGUSR2,      // Custom signal 2.
  kPipe = SIGPIPE,       // Broken pipe (typically ignored).
};

// Signal handler callback type.
using SignalCallback = std::function<void(Signal)>;

// Thread-safe signal handler manager.
// Registers signal handlers and dispatches to user callbacks.
class SignalHandler {
 public:
  // Get singleton instance.
  static SignalHandler& instance();

  // Register a callback for a specific signal.
  // Multiple callbacks can be registered for the same signal.
  void on(Signal sig, SignalCallback callback);

  // Remove all callbacks for a signal.
  void off(Signal sig);

  // Check if a signal was received (for polling).
  bool is_signaled(Signal sig) const;

  // Clear the signaled flag for a signal.
  void clear(Signal sig);

  // Check if any termination signal was received (SIGINT or SIGTERM).
  bool should_terminate() const;

  // Block all registered signals in the current thread.
  void block_signals();

  // Unblock all registered signals in the current thread.
  void unblock_signals();

  // Wait for any signal (blocking).
  Signal wait();

  // Setup default handlers (ignore SIGPIPE, handle SIGINT/SIGTERM).
  void setup_defaults();

  // Restore original signal handlers.
  void restore();

 public:
  // Non-copyable, non-movable.
  SignalHandler(const SignalHandler&) = delete;
  SignalHandler& operator=(const SignalHandler&) = delete;
  SignalHandler(SignalHandler&&) = delete;
  SignalHandler& operator=(SignalHandler&&) = delete;

 private:
  SignalHandler();
  ~SignalHandler();

  void install_handler(Signal sig);
  static void signal_handler(int signum);

  std::unordered_map<int, std::vector<SignalCallback>> callbacks_;
  std::unordered_map<int, struct sigaction> original_handlers_;

  // Atomic flags for each signal.
  static std::atomic<bool> interrupt_flag_;
  static std::atomic<bool> terminate_flag_;
  static std::atomic<bool> hangup_flag_;
  static std::atomic<bool> user1_flag_;
  static std::atomic<bool> user2_flag_;

  sigset_t original_mask_{};
  bool mask_saved_{false};
};

// RAII signal blocker.
class SignalBlocker {
 public:
  SignalBlocker();
  ~SignalBlocker();

  SignalBlocker(const SignalBlocker&) = delete;
  SignalBlocker& operator=(const SignalBlocker&) = delete;
  SignalBlocker(SignalBlocker&&) = delete;
  SignalBlocker& operator=(SignalBlocker&&) = delete;
};

}  // namespace veil::signal
