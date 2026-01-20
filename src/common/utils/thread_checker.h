#pragma once

#include <cassert>
#include <thread>

namespace veil::utils {

/**
 * Thread ownership checker for enforcing single-threaded access patterns.
 *
 * This utility class helps enforce the documented thread model by providing
 * runtime assertions in debug builds. When a ThreadChecker is created, it
 * records the current thread ID. Subsequent calls to check() will assert
 * that they are called from the same thread.
 *
 * In release builds (NDEBUG defined), all operations are no-ops with zero
 * overhead.
 *
 * Usage:
 * @code
 * class SingleThreadedComponent {
 *  public:
 *   void process() {
 *     VEIL_DCHECK_THREAD(thread_checker_);
 *     // ... component logic that must run on owner thread ...
 *   }
 *
 *  private:
 *   VEIL_THREAD_CHECKER(thread_checker_);
 * };
 * @endcode
 *
 * Thread Safety:
 *   This class itself is NOT thread-safe. It is designed to detect
 *   violations of single-threaded access patterns, not to protect against them.
 *
 * @see docs/thread_model.md for the VEIL threading model documentation.
 */
class ThreadChecker {
 public:
#ifndef NDEBUG
  /**
   * Construct a ThreadChecker bound to the current thread.
   */
  ThreadChecker() noexcept : owner_thread_id_(std::this_thread::get_id()) {}

  /**
   * Move constructor. The new ThreadChecker takes ownership from the source.
   * After move, the source is detached (will accept any thread).
   */
  ThreadChecker(ThreadChecker&& other) noexcept : owner_thread_id_(other.owner_thread_id_) {
    other.detach();
  }

  /**
   * Move assignment. The target takes ownership from the source.
   * After move, the source is detached.
   */
  ThreadChecker& operator=(ThreadChecker&& other) noexcept {
    if (this != &other) {
      owner_thread_id_ = other.owner_thread_id_;
      other.detach();
    }
    return *this;
  }

  // Disable copy (thread ownership is not copyable)
  ThreadChecker(const ThreadChecker&) = delete;
  ThreadChecker& operator=(const ThreadChecker&) = delete;

  /**
   * Check that the current thread is the owner thread.
   * In debug builds, this asserts if called from a different thread.
   * In release builds, this is a no-op.
   */
  void check() const noexcept {
    assert(is_owner_thread() && "ThreadChecker: called from wrong thread!");
  }

  /**
   * Returns true if the current thread is the owner thread.
   */
  [[nodiscard]] bool is_owner_thread() const noexcept {
    return std::this_thread::get_id() == owner_thread_id_;
  }

  /**
   * Detach the checker from its current thread.
   * After this call, the checker is in an unbound state and
   * subsequent calls to check() will accept any thread.
   * The next call to rebind() or rebind_to_current() will
   * establish a new owner thread.
   *
   * This is useful when transferring ownership of an object
   * between threads in a controlled manner.
   */
  void detach() noexcept { owner_thread_id_ = std::thread::id{}; }

  /**
   * Rebind the checker to the current thread.
   * This establishes the current thread as the new owner.
   * Useful when intentionally transferring ownership between threads.
   */
  void rebind_to_current() noexcept { owner_thread_id_ = std::this_thread::get_id(); }

  /**
   * Get the owner thread ID (for debugging/logging).
   */
  [[nodiscard]] std::thread::id owner_thread_id() const noexcept { return owner_thread_id_; }

 private:
  std::thread::id owner_thread_id_;

#else  // NDEBUG - Release build: zero overhead

 public:
  ThreadChecker() noexcept = default;
  ThreadChecker(ThreadChecker&&) noexcept = default;
  ThreadChecker& operator=(ThreadChecker&&) noexcept = default;
  ThreadChecker(const ThreadChecker&) = delete;
  ThreadChecker& operator=(const ThreadChecker&) = delete;

  void check() const noexcept {}
  [[nodiscard]] static constexpr bool is_owner_thread() noexcept { return true; }
  void detach() noexcept {}
  void rebind_to_current() noexcept {}
  [[nodiscard]] static std::thread::id owner_thread_id() noexcept { return std::thread::id{}; }

#endif  // NDEBUG
};

/**
 * Scoped thread checker that binds to current thread on construction
 * and automatically checks on destruction (useful for RAII patterns).
 */
class ScopedThreadCheck {
 public:
#ifndef NDEBUG
  explicit ScopedThreadCheck(const ThreadChecker& checker) noexcept : checker_(&checker) {
    checker_->check();
  }

  ~ScopedThreadCheck() noexcept { checker_->check(); }

  ScopedThreadCheck(const ScopedThreadCheck&) = delete;
  ScopedThreadCheck& operator=(const ScopedThreadCheck&) = delete;
  ScopedThreadCheck(ScopedThreadCheck&&) = delete;
  ScopedThreadCheck& operator=(ScopedThreadCheck&&) = delete;

 private:
  const ThreadChecker* checker_;

#else  // NDEBUG - Release build: zero overhead

 public:
  explicit ScopedThreadCheck(const ThreadChecker& /*checker*/) noexcept {}
  ~ScopedThreadCheck() noexcept = default;
  ScopedThreadCheck(const ScopedThreadCheck&) = delete;
  ScopedThreadCheck& operator=(const ScopedThreadCheck&) = delete;
  ScopedThreadCheck(ScopedThreadCheck&&) = delete;
  ScopedThreadCheck& operator=(ScopedThreadCheck&&) = delete;

#endif  // NDEBUG
};

}  // namespace veil::utils

/**
 * Convenience macros for thread checking.
 *
 * VEIL_THREAD_CHECKER(name) - Declare a ThreadChecker member variable
 * VEIL_DCHECK_THREAD(checker) - Assert current thread owns the checker (debug only)
 * VEIL_DCHECK_THREAD_SCOPE(checker) - Create scoped thread check (debug only)
 */
#ifndef NDEBUG
#define VEIL_THREAD_CHECKER(name) ::veil::utils::ThreadChecker name
#define VEIL_DCHECK_THREAD(checker) (checker).check()
#define VEIL_DCHECK_THREAD_SCOPE(checker) \
  ::veil::utils::ScopedThreadCheck veil_scoped_thread_check_##__LINE__(checker)
#else
#define VEIL_THREAD_CHECKER(name) ::veil::utils::ThreadChecker name
#define VEIL_DCHECK_THREAD(checker) ((void)0)
#define VEIL_DCHECK_THREAD_SCOPE(checker) ((void)0)
#endif
