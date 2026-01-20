#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

#include "transport/mux/frame.h"

namespace veil::mux {

// Configuration for ACK scheduling.
struct AckSchedulerConfig {
  // Maximum delay before sending ACK (delayed ACK).
  std::chrono::milliseconds max_ack_delay{50};

  // Number of packets to receive before sending immediate ACK.
  std::uint32_t ack_every_n_packets{2};

  // Enable ACK coalescing (combine multiple ACKs into one).
  bool enable_coalescing{true};

  // Maximum number of pending ACKs before forcing send.
  std::uint32_t max_pending_acks{8};

  // Enable immediate ACK for out-of-order packets.
  bool immediate_ack_on_gap{true};

  // Enable immediate ACK for FIN packets.
  bool immediate_ack_on_fin{true};
};

// Statistics for ACK scheduling.
struct AckSchedulerStats {
  std::uint64_t acks_sent{0};
  std::uint64_t acks_coalesced{0};
  std::uint64_t acks_delayed{0};
  std::uint64_t acks_immediate{0};
  std::uint64_t gaps_detected{0};
};

// Manages ACK scheduling with delayed-ACK and coalescing.
class AckScheduler {
 public:
  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;
  using AckCallback = std::function<void(std::uint64_t stream_id, std::uint64_t ack_seq, std::uint32_t bitmap)>;

  explicit AckScheduler(AckSchedulerConfig config = {},
                        std::function<TimePoint()> now_fn = Clock::now);

  // Record receipt of a data packet.
  // Returns true if an ACK should be sent immediately.
  bool on_packet_received(std::uint64_t stream_id, std::uint64_t sequence, bool fin = false);

  // Check if it's time to send a delayed ACK.
  // Returns stream_id if ACK is due, nullopt otherwise.
  std::optional<std::uint64_t> check_ack_timer();

  // Get the ACK frame to send for a stream.
  // Call this when on_packet_received returns true or check_ack_timer returns a stream_id.
  std::optional<AckFrame> get_pending_ack(std::uint64_t stream_id);

  // Mark that an ACK was sent for a stream.
  void ack_sent(std::uint64_t stream_id);

  // Get time until next ACK is due (for timer scheduling).
  std::optional<std::chrono::milliseconds> time_until_next_ack() const;

  // Get statistics.
  const AckSchedulerStats& stats() const { return stats_; }

  // Reset state for a stream.
  void reset_stream(std::uint64_t stream_id);

 private:
  struct StreamAckState {
    std::uint64_t highest_received{0};
    std::uint32_t received_bitmap{0};
    std::uint32_t packets_since_ack{0};
    TimePoint first_unacked_time;
    bool needs_ack{false};
    bool gap_detected{false};
  };

  void update_bitmap(StreamAckState& state, std::uint64_t sequence);
  bool should_send_immediate_ack(const StreamAckState& state, bool fin) const;

  AckSchedulerConfig config_;
  std::function<TimePoint()> now_fn_;
  std::vector<std::pair<std::uint64_t, StreamAckState>> streams_;
  AckSchedulerStats stats_;
};

}  // namespace veil::mux
