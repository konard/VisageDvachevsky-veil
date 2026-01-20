// Experiment to reproduce the replay cache deadlock
// This simulates the ConstantTimeResponse test scenario

#include <iostream>
#include <chrono>
#include <thread>
#include "../src/common/handshake/handshake_replay_cache.h"
#include "../src/common/crypto/crypto_engine.h"

int main() {
    std::cout << "Testing replay cache for deadlock...\n";

    veil::handshake::HandshakeReplayCache cache(4096, std::chrono::milliseconds(60000));

    std::array<std::uint8_t, 32> ephemeral_key{};

    // Simulate the test: call mark_and_check 100 times
    // The 100th call should trigger cleanup_expired and deadlock
    for (int i = 0; i < 150; ++i) {
        std::cout << "Iteration " << (i + 1) << "... ";
        std::cout.flush();

        // Each iteration uses a different key to avoid replay detection
        ephemeral_key[0] = static_cast<std::uint8_t>(i);

        auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()
        ).count();

        bool is_replay = cache.mark_and_check(static_cast<std::uint64_t>(now_ms), ephemeral_key);

        std::cout << (is_replay ? "REPLAY" : "OK") << "\n";

        if (i == 99) {
            std::cout << "*** On iteration 100 - this is where deadlock should occur ***\n";
        }
    }

    std::cout << "Test completed successfully (no deadlock)\n";
    return 0;
}
