#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <vector>

namespace veil::mux {

// Drop policy when buffer is full.
enum class DropPolicy : std::uint8_t {
  kOldest = 0,      // Drop oldest packets first (FIFO)
  kNewest = 1,      // Drop newest packets (reject new inserts)
  kLowPriority = 2  // Drop non-critical packets first (heartbeats, keepalives)
};

// Configuration for retransmission behavior.
struct RetransmitConfig {
  // Initial RTT estimate in milliseconds.
  std::chrono::milliseconds initial_rtt{100};
  // Minimum RTO (retransmit timeout).
  std::chrono::milliseconds min_rto{50};
  // Maximum RTO.
  std::chrono::milliseconds max_rto{10000};
  // Maximum number of retransmit attempts before giving up.
  std::uint32_t max_retries{5};
  // Maximum bytes buffered for retransmission.
  std::size_t max_buffer_bytes{1 << 20};  // 1 MB
  // Exponential backoff factor (multiplied on each retry).
  double backoff_factor{2.0};
  // RTT smoothing factor (alpha for EWMA).
  double rtt_alpha{0.125};
  // RTT variance factor (beta for EWMA).
  double rtt_beta{0.25};

  // ========== Hardening options (Stage 4) ==========

  // Maximum number of pending packets (0 = unlimited).
  std::size_t max_pending_count{10000};
  // High water mark for buffer (triggers aggressive cleanup).
  std::size_t high_water_mark{static_cast<std::size_t>(800) * 1024};  // 800 KB
  // Low water mark for buffer (stops aggressive cleanup).
  std::size_t low_water_mark{static_cast<std::size_t>(500) * 1024};   // 500 KB
  // Drop policy when buffer is full.
  DropPolicy drop_policy{DropPolicy::kOldest};
  // Enable burst protection (rate limit inserts during congestion).
  bool enable_burst_protection{true};
  // Maximum insert rate per second (0 = unlimited).
  std::uint32_t max_insert_rate{5000};
};

// Packet priority for drop policy.
enum class PacketPriority : std::uint8_t {
  kLow = 0,       // Heartbeats, keepalives
  kNormal = 1,    // Regular data
  kHigh = 2,      // Control frames, session-critical
  kCritical = 3   // Never drop (handshake, session setup)
};

// Entry representing a packet awaiting acknowledgment.
struct PendingPacket {
  std::uint64_t sequence{0};
  std::vector<std::uint8_t> data;
  std::chrono::steady_clock::time_point first_sent;
  std::chrono::steady_clock::time_point last_sent;
  std::chrono::steady_clock::time_point next_retry;
  std::uint32_t retry_count{0};
  PacketPriority priority{PacketPriority::kNormal};  // For drop policy
};

// Statistics for observability.
struct RetransmitStats {
  std::uint64_t packets_sent{0};
  std::uint64_t packets_acked{0};
  std::uint64_t packets_retransmitted{0};
  std::uint64_t packets_dropped{0};
  std::uint64_t bytes_sent{0};
  std::uint64_t bytes_retransmitted{0};

  // Hardening statistics.
  std::uint64_t packets_dropped_buffer_full{0};
  std::uint64_t packets_dropped_rate_limit{0};
  std::uint64_t packets_dropped_max_retries{0};
  std::uint64_t cleanup_invocations{0};
  std::uint64_t high_water_mark_hits{0};
};

/**
 * Manages a buffer of unacknowledged packets with RTT estimation and retransmission.
 *
 * Thread Safety:
 *   This class is NOT thread-safe. All methods must be called from a single
 *   thread (typically the event loop thread). The buffer contains internal
 *   state (pending packets, RTT estimates, rate limiting state) that is not
 *   protected by locks.
 *
 * @see docs/thread_model.md for the VEIL threading model documentation.
 */
class RetransmitBuffer {
 public:
  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;
  using Duration = Clock::duration;

  explicit RetransmitBuffer(RetransmitConfig config = {},
                            std::function<TimePoint()> now_fn = Clock::now);

  // Insert a newly sent packet into the buffer.
  // Returns false if buffer is full (exceeds max_buffer_bytes).
  bool insert(std::uint64_t sequence, std::vector<std::uint8_t> data);

  // Insert a packet with specified priority.
  bool insert_with_priority(std::uint64_t sequence, std::vector<std::uint8_t> data,
                            PacketPriority priority);

  // Acknowledge a packet. Updates RTT estimate and removes from buffer.
  // Returns true if the sequence was found and acknowledged.
  bool acknowledge(std::uint64_t sequence);

  // Acknowledge all packets up to and including sequence (cumulative ACK).
  void acknowledge_cumulative(std::uint64_t sequence);

  // Get packets that need retransmission now.
  // Returns references to packets whose next_retry has passed.
  std::vector<const PendingPacket*> get_packets_to_retransmit();

  // Mark a packet as retransmitted (updates retry count and next_retry time).
  // Returns false if max retries exceeded (packet should be dropped).
  bool mark_retransmitted(std::uint64_t sequence);

  // Remove a packet that has exceeded max retries.
  void drop_packet(std::uint64_t sequence);

  // Get current RTT estimate.
  std::chrono::milliseconds estimated_rtt() const { return estimated_rtt_; }

  // Get current RTO (retransmit timeout).
  std::chrono::milliseconds current_rto() const { return current_rto_; }

  // Get current buffer utilization.
  std::size_t buffered_bytes() const { return buffered_bytes_; }
  std::size_t pending_count() const { return pending_.size(); }

  // Get statistics.
  const RetransmitStats& stats() const { return stats_; }

  // Check if buffer has capacity for more data.
  bool has_capacity(std::size_t bytes) const {
    return buffered_bytes_ + bytes <= config_.max_buffer_bytes;
  }

  // Check if buffer is above high water mark.
  bool is_above_high_water() const { return buffered_bytes_ >= config_.high_water_mark; }

  // Check if buffer is below low water mark.
  bool is_below_low_water() const { return buffered_bytes_ <= config_.low_water_mark; }

  // Force cleanup of buffer (drops packets according to policy).
  // Returns number of packets dropped.
  std::size_t force_cleanup(std::size_t target_bytes);

  // Get buffer utilization ratio [0.0, 1.0].
  double utilization() const {
    if (config_.max_buffer_bytes == 0) return 0.0;
    return static_cast<double>(buffered_bytes_) / static_cast<double>(config_.max_buffer_bytes);
  }

 private:
  void update_rtt(std::chrono::milliseconds sample);
  std::chrono::milliseconds calculate_rto() const;

  // Internal: try to make room for new data.
  bool make_room(std::size_t bytes_needed);

  // Internal: check rate limit.
  bool check_rate_limit();

  RetransmitConfig config_;
  std::function<TimePoint()> now_fn_;

  std::map<std::uint64_t, PendingPacket> pending_;
  std::size_t buffered_bytes_{0};

  // RTT estimation (RFC 6298 style)
  std::chrono::milliseconds estimated_rtt_;
  std::chrono::milliseconds rtt_variance_{0};
  std::chrono::milliseconds current_rto_;
  bool rtt_initialized_{false};

  // Rate limiting state.
  TimePoint rate_limit_window_start_;
  std::uint32_t inserts_in_window_{0};

  RetransmitStats stats_;
};

}  // namespace veil::mux
