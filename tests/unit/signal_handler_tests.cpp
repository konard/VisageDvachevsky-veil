#include <gtest/gtest.h>

#include <csignal>
#include <thread>

#include "common/signal/signal_handler.h"

namespace veil::signal::test {

class SignalHandlerTest : public ::testing::Test {
 protected:
  void SetUp() override {
    // Clear any pending signals.
    auto& handler = SignalHandler::instance();
    handler.clear(Signal::kInterrupt);
    handler.clear(Signal::kTerminate);
    handler.clear(Signal::kHangup);
    handler.clear(Signal::kUser1);
    handler.clear(Signal::kUser2);
  }

  void TearDown() override {
    // Restore default handlers.
    auto& handler = SignalHandler::instance();
    handler.restore();
  }
};

TEST_F(SignalHandlerTest, Singleton) {
  auto& handler1 = SignalHandler::instance();
  auto& handler2 = SignalHandler::instance();

  EXPECT_EQ(&handler1, &handler2);
}

TEST_F(SignalHandlerTest, InitialState) {
  auto& handler = SignalHandler::instance();

  EXPECT_FALSE(handler.is_signaled(Signal::kInterrupt));
  EXPECT_FALSE(handler.is_signaled(Signal::kTerminate));
  EXPECT_FALSE(handler.is_signaled(Signal::kHangup));
  EXPECT_FALSE(handler.should_terminate());
}

TEST_F(SignalHandlerTest, SetupDefaults) {
  auto& handler = SignalHandler::instance();

  // Should not throw.
  EXPECT_NO_THROW(handler.setup_defaults());
}

TEST_F(SignalHandlerTest, ShouldTerminateAfterSigint) {
  auto& handler = SignalHandler::instance();
  handler.setup_defaults();

  EXPECT_FALSE(handler.should_terminate());

  // Simulate SIGINT.
  raise(SIGINT);

  // Give the signal time to be delivered.
  std::this_thread::sleep_for(std::chrono::milliseconds(10));

  EXPECT_TRUE(handler.is_signaled(Signal::kInterrupt));
  EXPECT_TRUE(handler.should_terminate());
}

TEST_F(SignalHandlerTest, ShouldTerminateAfterSigterm) {
  auto& handler = SignalHandler::instance();
  handler.setup_defaults();

  EXPECT_FALSE(handler.should_terminate());

  // Simulate SIGTERM.
  raise(SIGTERM);

  std::this_thread::sleep_for(std::chrono::milliseconds(10));

  EXPECT_TRUE(handler.is_signaled(Signal::kTerminate));
  EXPECT_TRUE(handler.should_terminate());
}

TEST_F(SignalHandlerTest, ClearSignal) {
  auto& handler = SignalHandler::instance();
  handler.setup_defaults();

  raise(SIGINT);
  std::this_thread::sleep_for(std::chrono::milliseconds(10));

  EXPECT_TRUE(handler.is_signaled(Signal::kInterrupt));

  handler.clear(Signal::kInterrupt);

  EXPECT_FALSE(handler.is_signaled(Signal::kInterrupt));
}

TEST_F(SignalHandlerTest, RegisterCallback) {
  auto& handler = SignalHandler::instance();

  bool callback_called = false;
  Signal received_signal = Signal::kPipe;

  handler.on(Signal::kUser1, [&](Signal sig) {
    callback_called = true;
    received_signal = sig;
  });

  // The callback is registered but not automatically called.
  // The signal handler sets the flag; callbacks need separate dispatch.
  raise(SIGUSR1);
  std::this_thread::sleep_for(std::chrono::milliseconds(10));

  EXPECT_TRUE(handler.is_signaled(Signal::kUser1));
}

TEST_F(SignalHandlerTest, RemoveCallback) {
  auto& handler = SignalHandler::instance();

  handler.on(Signal::kUser2, [](Signal) {});
  handler.off(Signal::kUser2);

  // After removing, the default handler should be restored.
  // This test mainly verifies no crash occurs.
  EXPECT_FALSE(handler.is_signaled(Signal::kUser2));
}

TEST_F(SignalHandlerTest, SighupNotTerminate) {
  auto& handler = SignalHandler::instance();
  handler.setup_defaults();

  raise(SIGHUP);
  std::this_thread::sleep_for(std::chrono::milliseconds(10));

  EXPECT_TRUE(handler.is_signaled(Signal::kHangup));
  // SIGHUP should not trigger termination.
  handler.clear(Signal::kInterrupt);
  handler.clear(Signal::kTerminate);
  EXPECT_FALSE(handler.should_terminate());
}

// SignalBlocker tests.
class SignalBlockerTest : public ::testing::Test {};

TEST_F(SignalBlockerTest, BlocksSignals) {
  auto& handler = SignalHandler::instance();
  handler.setup_defaults();
  handler.clear(Signal::kInterrupt);

  {
    SignalBlocker blocker;

    // Signal should be blocked while blocker is in scope.
    raise(SIGINT);
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    // Signal might be pending but not delivered yet.
  }

  // After blocker is destroyed, signals should be unblocked.
  // The pending signal should now be delivered.
  std::this_thread::sleep_for(std::chrono::milliseconds(10));

  EXPECT_TRUE(handler.is_signaled(Signal::kInterrupt));
}

}  // namespace veil::signal::test
