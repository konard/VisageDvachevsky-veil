#pragma once

#include <array>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <mutex>
#include <string>

#include "common/obfuscation/obfuscation_profile.h"

namespace veil::transport {

// Extended transport statistics for DPI/ML validation and debugging.
// Thread-safe for concurrent access.
struct TransportMetrics {
  // Packet size distribution.
  double mean_packet_size{0.0};
  double packet_size_stddev{0.0};
  std::uint16_t min_packet_size{0};
  std::uint16_t max_packet_size{0};
  std::array<std::uint64_t, 16> packet_size_histogram{};  // 64-byte buckets

  // Inter-arrival time distribution.
  double mean_inter_arrival_ms{0.0};
  double inter_arrival_stddev{0.0};
  std::array<std::uint64_t, 16> inter_arrival_histogram{};  // 10ms buckets

  // RTT statistics.
  double srtt_ms{0.0};     // Smoothed RTT
  double rttvar_ms{0.0};   // RTT variance
  double min_rtt_ms{0.0};
  double max_rtt_ms{0.0};

  // Retransmit statistics.
  std::uint64_t retransmit_count{0};
  std::uint64_t retransmit_bytes{0};
  double retransmit_rate{0.0};  // retransmits / total_packets

  // ACK statistics.
  std::uint64_t acks_sent{0};
  std::uint64_t acks_received{0};
  std::uint64_t acks_suppressed{0};  // For delayed ACK
  double ack_rate{0.0};              // acks / data_packets

  // Heartbeat statistics.
  std::uint64_t heartbeats_sent{0};
  std::uint64_t heartbeats_received{0};
  double heartbeat_ratio{0.0};

  // Padding/prefix statistics.
  std::uint64_t total_padding_bytes{0};
  std::uint64_t total_prefix_bytes{0};
  double avg_padding_per_packet{0.0};
  double avg_prefix_per_packet{0.0};
  std::array<std::uint64_t, 16> padding_size_histogram{};  // 64-byte buckets

  // Jitter statistics.
  std::uint64_t jitter_applied_count{0};
  double avg_jitter_ms{0.0};
  double jitter_stddev{0.0};

  // Overall counters.
  std::uint64_t packets_sent{0};
  std::uint64_t packets_received{0};
  std::uint64_t bytes_sent{0};
  std::uint64_t bytes_received{0};
  std::uint64_t packets_dropped{0};
  std::uint64_t decrypt_failures{0};
  std::uint64_t replay_rejections{0};

  // Session statistics.
  std::uint64_t session_rotations{0};
  std::chrono::steady_clock::time_point session_start;
  std::chrono::seconds session_duration{0};
};

// Statistics collector for transport layer.
// Tracks metrics for DPI resistance validation and performance analysis.
class TransportStatsCollector {
 public:
  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;

  TransportStatsCollector();

  // Record a sent packet.
  void record_packet_sent(std::uint16_t size, std::uint16_t padding_size, std::uint16_t prefix_size,
                          bool is_heartbeat, std::uint16_t jitter_ms = 0);

  // Record a received packet.
  void record_packet_received(std::uint16_t size, bool is_heartbeat);

  // Record packet drop.
  void record_packet_dropped();

  // Record decrypt failure.
  void record_decrypt_failure();

  // Record replay rejection.
  void record_replay_rejection();

  // Record a retransmit.
  void record_retransmit(std::uint16_t size);

  // Record an ACK sent.
  void record_ack_sent();

  // Record an ACK received.
  void record_ack_received();

  // Record an ACK suppressed (delayed ACK).
  void record_ack_suppressed();

  // Record RTT sample (in milliseconds).
  void record_rtt_sample(double rtt_ms);

  // Record session rotation.
  void record_session_rotation();

  // Get current metrics snapshot (thread-safe copy).
  TransportMetrics get_metrics() const;

  // Reset all statistics.
  void reset();

  // Generate JSON string for metrics export.
  std::string to_json() const;

  // Generate spdlog-compatible debug dump.
  std::string to_debug_string() const;

 private:
  void update_send_interval();

  mutable std::mutex mutex_;
  TransportMetrics metrics_;

  // Internal tracking.
  TimePoint last_send_time_;
  TimePoint session_start_time_;
  std::uint64_t send_count_{0};  // For interval tracking
  double interval_m2_{0.0};      // For Welford's algorithm
  double packet_size_m2_{0.0};
  double jitter_m2_{0.0};
  double rtt_m2_{0.0};
  std::uint64_t rtt_sample_count_{0};
  bool first_rtt_{true};
};

// Global transport stats instance (for convenience).
TransportStatsCollector& global_transport_stats();

}  // namespace veil::transport
