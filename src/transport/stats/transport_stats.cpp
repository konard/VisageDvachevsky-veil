#include "transport/stats/transport_stats.h"

#include <algorithm>
#include <cmath>
#include <iomanip>
#include <sstream>

namespace veil::transport {

TransportStatsCollector::TransportStatsCollector() {
  session_start_time_ = Clock::now();
  last_send_time_ = session_start_time_;
  metrics_.session_start = session_start_time_;
}

void TransportStatsCollector::record_packet_sent(std::uint16_t size, std::uint16_t padding_size,
                                                  std::uint16_t prefix_size, bool is_heartbeat,
                                                  std::uint16_t jitter_ms) {
  std::lock_guard<std::mutex> lock(mutex_);

  ++metrics_.packets_sent;
  metrics_.bytes_sent += size;

  // Update packet size statistics (Welford's algorithm).
  const auto n = static_cast<double>(metrics_.packets_sent);
  const auto delta = static_cast<double>(size) - metrics_.mean_packet_size;
  metrics_.mean_packet_size += delta / n;
  const auto delta2 = static_cast<double>(size) - metrics_.mean_packet_size;
  packet_size_m2_ += delta * delta2;

  if (metrics_.packets_sent > 1) {
    metrics_.packet_size_stddev = std::sqrt(packet_size_m2_ / (n - 1.0));
  }

  // Update min/max.
  if (metrics_.packets_sent == 1 || size < metrics_.min_packet_size) {
    metrics_.min_packet_size = size;
  }
  if (size > metrics_.max_packet_size) {
    metrics_.max_packet_size = size;
  }

  // Update packet size histogram.
  const auto bucket = std::min(static_cast<std::size_t>(size / 64), std::size_t{15});
  ++metrics_.packet_size_histogram[bucket];

  // Update inter-arrival time.
  update_send_interval();

  // Update padding statistics.
  metrics_.total_padding_bytes += padding_size;
  metrics_.avg_padding_per_packet = static_cast<double>(metrics_.total_padding_bytes) / n;

  const auto padding_bucket = std::min(static_cast<std::size_t>(padding_size / 64), std::size_t{15});
  ++metrics_.padding_size_histogram[padding_bucket];

  // Update prefix statistics.
  metrics_.total_prefix_bytes += prefix_size;
  metrics_.avg_prefix_per_packet = static_cast<double>(metrics_.total_prefix_bytes) / n;

  // Update heartbeat statistics.
  if (is_heartbeat) {
    ++metrics_.heartbeats_sent;
  }
  metrics_.heartbeat_ratio = static_cast<double>(metrics_.heartbeats_sent) / n;

  // Update jitter statistics.
  if (jitter_ms > 0) {
    ++metrics_.jitter_applied_count;
    const auto jitter_n = static_cast<double>(metrics_.jitter_applied_count);
    const auto jitter_delta = static_cast<double>(jitter_ms) - metrics_.avg_jitter_ms;
    metrics_.avg_jitter_ms += jitter_delta / jitter_n;
    const auto jitter_delta2 = static_cast<double>(jitter_ms) - metrics_.avg_jitter_ms;
    jitter_m2_ += jitter_delta * jitter_delta2;

    if (metrics_.jitter_applied_count > 1) {
      metrics_.jitter_stddev = std::sqrt(jitter_m2_ / (jitter_n - 1.0));
    }
  }

  // Update session duration.
  metrics_.session_duration = std::chrono::duration_cast<std::chrono::seconds>(
      Clock::now() - session_start_time_);
}

void TransportStatsCollector::record_packet_received(std::uint16_t size, bool is_heartbeat) {
  std::lock_guard<std::mutex> lock(mutex_);

  ++metrics_.packets_received;
  metrics_.bytes_received += size;

  if (is_heartbeat) {
    ++metrics_.heartbeats_received;
  }
}

void TransportStatsCollector::record_packet_dropped() {
  std::lock_guard<std::mutex> lock(mutex_);
  ++metrics_.packets_dropped;
}

void TransportStatsCollector::record_decrypt_failure() {
  std::lock_guard<std::mutex> lock(mutex_);
  ++metrics_.decrypt_failures;
}

void TransportStatsCollector::record_replay_rejection() {
  std::lock_guard<std::mutex> lock(mutex_);
  ++metrics_.replay_rejections;
}

void TransportStatsCollector::record_retransmit(std::uint16_t size) {
  std::lock_guard<std::mutex> lock(mutex_);

  ++metrics_.retransmit_count;
  metrics_.retransmit_bytes += size;

  if (metrics_.packets_sent > 0) {
    metrics_.retransmit_rate =
        static_cast<double>(metrics_.retransmit_count) / static_cast<double>(metrics_.packets_sent);
  }
}

void TransportStatsCollector::record_ack_sent() {
  std::lock_guard<std::mutex> lock(mutex_);
  ++metrics_.acks_sent;

  // Calculate ACK rate (acks / data packets received).
  if (metrics_.packets_received > 0) {
    metrics_.ack_rate =
        static_cast<double>(metrics_.acks_sent) / static_cast<double>(metrics_.packets_received);
  }
}

void TransportStatsCollector::record_ack_received() {
  std::lock_guard<std::mutex> lock(mutex_);
  ++metrics_.acks_received;
}

void TransportStatsCollector::record_ack_suppressed() {
  std::lock_guard<std::mutex> lock(mutex_);
  ++metrics_.acks_suppressed;
}

void TransportStatsCollector::record_rtt_sample(double rtt_ms) {
  std::lock_guard<std::mutex> lock(mutex_);

  ++rtt_sample_count_;
  const auto n = static_cast<double>(rtt_sample_count_);

  // Welford's algorithm for RTT.
  const auto delta = rtt_ms - metrics_.srtt_ms;
  metrics_.srtt_ms += delta / n;
  const auto delta2 = rtt_ms - metrics_.srtt_ms;
  rtt_m2_ += delta * delta2;

  if (rtt_sample_count_ > 1) {
    metrics_.rttvar_ms = std::sqrt(rtt_m2_ / (n - 1.0));
  }

  // Update min/max.
  if (first_rtt_ || rtt_ms < metrics_.min_rtt_ms) {
    metrics_.min_rtt_ms = rtt_ms;
  }
  if (first_rtt_ || rtt_ms > metrics_.max_rtt_ms) {
    metrics_.max_rtt_ms = rtt_ms;
  }
  first_rtt_ = false;
}

void TransportStatsCollector::record_session_rotation() {
  std::lock_guard<std::mutex> lock(mutex_);
  ++metrics_.session_rotations;
}

TransportMetrics TransportStatsCollector::get_metrics() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return metrics_;
}

void TransportStatsCollector::reset() {
  std::lock_guard<std::mutex> lock(mutex_);

  metrics_ = TransportMetrics{};
  session_start_time_ = Clock::now();
  last_send_time_ = session_start_time_;
  metrics_.session_start = session_start_time_;
  send_count_ = 0;
  interval_m2_ = 0.0;
  packet_size_m2_ = 0.0;
  jitter_m2_ = 0.0;
  rtt_m2_ = 0.0;
  rtt_sample_count_ = 0;
  first_rtt_ = true;
}

void TransportStatsCollector::update_send_interval() {
  const auto now = Clock::now();
  const auto interval_us =
      std::chrono::duration_cast<std::chrono::microseconds>(now - last_send_time_).count();
  const auto interval_ms = static_cast<double>(interval_us) / 1000.0;

  ++send_count_;
  if (send_count_ > 1) {
    const auto n = static_cast<double>(send_count_ - 1);  // Intervals = packets - 1
    const auto delta = interval_ms - metrics_.mean_inter_arrival_ms;
    metrics_.mean_inter_arrival_ms += delta / n;
    const auto delta2 = interval_ms - metrics_.mean_inter_arrival_ms;
    interval_m2_ += delta * delta2;

    if (send_count_ > 2) {
      metrics_.inter_arrival_stddev = std::sqrt(interval_m2_ / (n - 1.0));
    }

    // Update histogram.
    const auto bucket = std::min(static_cast<std::size_t>(interval_ms / 10.0), std::size_t{15});
    ++metrics_.inter_arrival_histogram[bucket];
  }

  last_send_time_ = now;
}

std::string TransportStatsCollector::to_json() const {
  std::lock_guard<std::mutex> lock(mutex_);

  std::ostringstream oss;
  oss << std::fixed << std::setprecision(3);
  oss << "{\n";
  oss << "  \"packet_size\": {\n";
  oss << "    \"mean\": " << metrics_.mean_packet_size << ",\n";
  oss << "    \"stddev\": " << metrics_.packet_size_stddev << ",\n";
  oss << "    \"min\": " << metrics_.min_packet_size << ",\n";
  oss << "    \"max\": " << metrics_.max_packet_size << "\n";
  oss << "  },\n";
  oss << "  \"inter_arrival_ms\": {\n";
  oss << "    \"mean\": " << metrics_.mean_inter_arrival_ms << ",\n";
  oss << "    \"stddev\": " << metrics_.inter_arrival_stddev << "\n";
  oss << "  },\n";
  oss << "  \"rtt_ms\": {\n";
  oss << "    \"srtt\": " << metrics_.srtt_ms << ",\n";
  oss << "    \"rttvar\": " << metrics_.rttvar_ms << ",\n";
  oss << "    \"min\": " << metrics_.min_rtt_ms << ",\n";
  oss << "    \"max\": " << metrics_.max_rtt_ms << "\n";
  oss << "  },\n";
  oss << "  \"retransmit\": {\n";
  oss << "    \"count\": " << metrics_.retransmit_count << ",\n";
  oss << "    \"bytes\": " << metrics_.retransmit_bytes << ",\n";
  oss << "    \"rate\": " << metrics_.retransmit_rate << "\n";
  oss << "  },\n";
  oss << "  \"ack\": {\n";
  oss << "    \"sent\": " << metrics_.acks_sent << ",\n";
  oss << "    \"received\": " << metrics_.acks_received << ",\n";
  oss << "    \"suppressed\": " << metrics_.acks_suppressed << ",\n";
  oss << "    \"rate\": " << metrics_.ack_rate << "\n";
  oss << "  },\n";
  oss << "  \"heartbeat\": {\n";
  oss << "    \"sent\": " << metrics_.heartbeats_sent << ",\n";
  oss << "    \"received\": " << metrics_.heartbeats_received << ",\n";
  oss << "    \"ratio\": " << metrics_.heartbeat_ratio << "\n";
  oss << "  },\n";
  oss << "  \"padding\": {\n";
  oss << "    \"total_bytes\": " << metrics_.total_padding_bytes << ",\n";
  oss << "    \"avg_per_packet\": " << metrics_.avg_padding_per_packet << "\n";
  oss << "  },\n";
  oss << "  \"prefix\": {\n";
  oss << "    \"total_bytes\": " << metrics_.total_prefix_bytes << ",\n";
  oss << "    \"avg_per_packet\": " << metrics_.avg_prefix_per_packet << "\n";
  oss << "  },\n";
  oss << "  \"jitter\": {\n";
  oss << "    \"applied_count\": " << metrics_.jitter_applied_count << ",\n";
  oss << "    \"avg_ms\": " << metrics_.avg_jitter_ms << ",\n";
  oss << "    \"stddev\": " << metrics_.jitter_stddev << "\n";
  oss << "  },\n";
  oss << "  \"counters\": {\n";
  oss << "    \"packets_sent\": " << metrics_.packets_sent << ",\n";
  oss << "    \"packets_received\": " << metrics_.packets_received << ",\n";
  oss << "    \"bytes_sent\": " << metrics_.bytes_sent << ",\n";
  oss << "    \"bytes_received\": " << metrics_.bytes_received << ",\n";
  oss << "    \"packets_dropped\": " << metrics_.packets_dropped << ",\n";
  oss << "    \"decrypt_failures\": " << metrics_.decrypt_failures << ",\n";
  oss << "    \"replay_rejections\": " << metrics_.replay_rejections << "\n";
  oss << "  },\n";
  oss << "  \"session\": {\n";
  oss << "    \"rotations\": " << metrics_.session_rotations << ",\n";
  oss << "    \"duration_sec\": " << metrics_.session_duration.count() << "\n";
  oss << "  }\n";
  oss << "}";

  return oss.str();
}

std::string TransportStatsCollector::to_debug_string() const {
  std::lock_guard<std::mutex> lock(mutex_);

  std::ostringstream oss;
  oss << std::fixed << std::setprecision(2);

  oss << "=== Transport Statistics ===\n";
  oss << "Packets: sent=" << metrics_.packets_sent << " recv=" << metrics_.packets_received
      << " dropped=" << metrics_.packets_dropped << "\n";
  oss << "Bytes: sent=" << metrics_.bytes_sent << " recv=" << metrics_.bytes_received << "\n";
  oss << "Packet size: mean=" << metrics_.mean_packet_size << " stddev=" << metrics_.packet_size_stddev
      << " min=" << metrics_.min_packet_size << " max=" << metrics_.max_packet_size << "\n";
  oss << "Inter-arrival: mean=" << metrics_.mean_inter_arrival_ms << "ms stddev="
      << metrics_.inter_arrival_stddev << "ms\n";
  oss << "RTT: srtt=" << metrics_.srtt_ms << "ms rttvar=" << metrics_.rttvar_ms
      << "ms min=" << metrics_.min_rtt_ms << " max=" << metrics_.max_rtt_ms << "\n";
  oss << "Retransmit: count=" << metrics_.retransmit_count << " bytes=" << metrics_.retransmit_bytes
      << " rate=" << metrics_.retransmit_rate << "\n";
  oss << "ACKs: sent=" << metrics_.acks_sent << " recv=" << metrics_.acks_received
      << " suppressed=" << metrics_.acks_suppressed << " rate=" << metrics_.ack_rate << "\n";
  oss << "Heartbeats: sent=" << metrics_.heartbeats_sent << " recv=" << metrics_.heartbeats_received
      << " ratio=" << metrics_.heartbeat_ratio << "\n";
  oss << "Padding: total=" << metrics_.total_padding_bytes << " avg=" << metrics_.avg_padding_per_packet << "\n";
  oss << "Prefix: total=" << metrics_.total_prefix_bytes << " avg=" << metrics_.avg_prefix_per_packet << "\n";
  oss << "Jitter: count=" << metrics_.jitter_applied_count << " avg=" << metrics_.avg_jitter_ms
      << "ms stddev=" << metrics_.jitter_stddev << "\n";
  oss << "Session: rotations=" << metrics_.session_rotations
      << " duration=" << metrics_.session_duration.count() << "s\n";
  oss << "Failures: decrypt=" << metrics_.decrypt_failures << " replay=" << metrics_.replay_rejections << "\n";

  return oss.str();
}

// Global instance.
TransportStatsCollector& global_transport_stats() {
  static TransportStatsCollector instance;
  return instance;
}

}  // namespace veil::transport
