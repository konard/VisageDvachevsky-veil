#include "common/signal/signal_handler.h"

#include <cstring>
#include <stdexcept>

#include "common/logging/logger.h"

namespace veil::signal {

// Static flag definitions.
std::atomic<bool> SignalHandler::interrupt_flag_{false};
std::atomic<bool> SignalHandler::terminate_flag_{false};
std::atomic<bool> SignalHandler::hangup_flag_{false};
std::atomic<bool> SignalHandler::user1_flag_{false};
std::atomic<bool> SignalHandler::user2_flag_{false};

SignalHandler& SignalHandler::instance() {
  static SignalHandler handler;
  return handler;
}

SignalHandler::SignalHandler() = default;

SignalHandler::~SignalHandler() { restore(); }

void SignalHandler::signal_handler(int signum) {
  switch (signum) {
    case SIGINT:
      interrupt_flag_.store(true, std::memory_order_release);
      break;
    case SIGTERM:
      terminate_flag_.store(true, std::memory_order_release);
      break;
    case SIGHUP:
      hangup_flag_.store(true, std::memory_order_release);
      break;
    case SIGUSR1:
      user1_flag_.store(true, std::memory_order_release);
      break;
    case SIGUSR2:
      user2_flag_.store(true, std::memory_order_release);
      break;
    default:
      break;
  }
}

void SignalHandler::install_handler(Signal sig) {
  const int signum = static_cast<int>(sig);

  // Save original handler if not already saved.
  if (original_handlers_.find(signum) == original_handlers_.end()) {
    struct sigaction old_action {};
    if (sigaction(signum, nullptr, &old_action) == 0) {
      original_handlers_[signum] = old_action;
    }
  }

  // Install our handler.
  struct sigaction action {};
  action.sa_handler = signal_handler;
  sigemptyset(&action.sa_mask);
  action.sa_flags = SA_RESTART;

  if (sigaction(signum, &action, nullptr) != 0) {
    LOG_ERROR("Failed to install signal handler for signal {}", signum);
  }
}

void SignalHandler::on(Signal sig, SignalCallback callback) {
  const int signum = static_cast<int>(sig);

  // Install handler if this is the first callback for this signal.
  if (callbacks_.find(signum) == callbacks_.end()) {
    install_handler(sig);
  }

  callbacks_[signum].push_back(std::move(callback));
  LOG_DEBUG("Registered callback for signal {}", signum);
}

void SignalHandler::off(Signal sig) {
  const int signum = static_cast<int>(sig);
  callbacks_.erase(signum);

  // Restore original handler.
  auto it = original_handlers_.find(signum);
  if (it != original_handlers_.end()) {
    sigaction(signum, &it->second, nullptr);
    original_handlers_.erase(it);
  }
}

bool SignalHandler::is_signaled(Signal sig) const {
  switch (sig) {
    case Signal::kInterrupt:
      return interrupt_flag_.load(std::memory_order_acquire);
    case Signal::kTerminate:
      return terminate_flag_.load(std::memory_order_acquire);
    case Signal::kHangup:
      return hangup_flag_.load(std::memory_order_acquire);
    case Signal::kUser1:
      return user1_flag_.load(std::memory_order_acquire);
    case Signal::kUser2:
      return user2_flag_.load(std::memory_order_acquire);
    default:
      return false;
  }
}

void SignalHandler::clear(Signal sig) {
  switch (sig) {
    case Signal::kInterrupt:
      interrupt_flag_.store(false, std::memory_order_release);
      break;
    case Signal::kTerminate:
      terminate_flag_.store(false, std::memory_order_release);
      break;
    case Signal::kHangup:
      hangup_flag_.store(false, std::memory_order_release);
      break;
    case Signal::kUser1:
      user1_flag_.store(false, std::memory_order_release);
      break;
    case Signal::kUser2:
      user2_flag_.store(false, std::memory_order_release);
      break;
    default:
      break;
  }
}

bool SignalHandler::should_terminate() const {
  return interrupt_flag_.load(std::memory_order_acquire) ||
         terminate_flag_.load(std::memory_order_acquire);
}

void SignalHandler::block_signals() {
  sigset_t mask;
  sigemptyset(&mask);

  // Add all registered signals to the mask.
  for (const auto& [signum, _] : callbacks_) {
    sigaddset(&mask, signum);
  }

  // Save original mask if not already saved.
  if (!mask_saved_) {
    pthread_sigmask(SIG_BLOCK, nullptr, &original_mask_);
    mask_saved_ = true;
  }

  pthread_sigmask(SIG_BLOCK, &mask, nullptr);
}

void SignalHandler::unblock_signals() {
  if (mask_saved_) {
    pthread_sigmask(SIG_SETMASK, &original_mask_, nullptr);
  }
}

Signal SignalHandler::wait() {
  sigset_t mask;
  sigemptyset(&mask);

  // Wait for any registered signal.
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGTERM);
  sigaddset(&mask, SIGHUP);
  sigaddset(&mask, SIGUSR1);
  sigaddset(&mask, SIGUSR2);

  int sig = 0;
  sigwait(&mask, &sig);

  return static_cast<Signal>(sig);
}

void SignalHandler::setup_defaults() {
  // Ignore SIGPIPE (common for network applications).
  struct sigaction ignore_action {};
  ignore_action.sa_handler = SIG_IGN;
  sigemptyset(&ignore_action.sa_mask);
  sigaction(SIGPIPE, &ignore_action, nullptr);

  // Install handlers for common termination signals.
  install_handler(Signal::kInterrupt);
  install_handler(Signal::kTerminate);
  install_handler(Signal::kHangup);

  LOG_INFO("Default signal handlers installed");
}

void SignalHandler::restore() {
  // Restore all original handlers.
  for (const auto& [signum, action] : original_handlers_) {
    sigaction(signum, &action, nullptr);
  }
  original_handlers_.clear();
  callbacks_.clear();

  // Restore signal mask.
  if (mask_saved_) {
    pthread_sigmask(SIG_SETMASK, &original_mask_, nullptr);
    mask_saved_ = false;
  }
}

// SignalBlocker implementation.

SignalBlocker::SignalBlocker() { SignalHandler::instance().block_signals(); }

SignalBlocker::~SignalBlocker() { SignalHandler::instance().unblock_signals(); }

}  // namespace veil::signal
