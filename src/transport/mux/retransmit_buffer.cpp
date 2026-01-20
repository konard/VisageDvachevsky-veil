#include "transport/mux/retransmit_buffer.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <map>
#include <utility>
#include <vector>

namespace veil::mux {

RetransmitBuffer::RetransmitBuffer(RetransmitConfig config, std::function<TimePoint()> now_fn)
    : config_(config),
      now_fn_(std::move(now_fn)),
      estimated_rtt_(config_.initial_rtt),
      current_rto_(config_.initial_rtt),
      rate_limit_window_start_(now_fn_()) {}

bool RetransmitBuffer::insert(std::uint64_t sequence, std::vector<std::uint8_t> data) {
  return insert_with_priority(sequence, std::move(data), PacketPriority::kNormal);
}

bool RetransmitBuffer::insert_with_priority(std::uint64_t sequence, std::vector<std::uint8_t> data,
                                             PacketPriority priority) {
  // Check rate limit first.
  if (!check_rate_limit()) {
    ++stats_.packets_dropped_rate_limit;
    ++stats_.packets_dropped;
    return false;
  }

  // Check pending count limit.
  if (config_.max_pending_count > 0 && pending_.size() >= config_.max_pending_count) {
    // Try to make room.
    if (!make_room(data.size())) {
      ++stats_.packets_dropped_buffer_full;
      ++stats_.packets_dropped;
      return false;
    }
  }

  // Check buffer size.
  if (buffered_bytes_ + data.size() > config_.max_buffer_bytes) {
    // Try to make room according to drop policy.
    if (!make_room(data.size())) {
      ++stats_.packets_dropped_buffer_full;
      ++stats_.packets_dropped;
      return false;
    }
  }

  // Check high water mark.
  if (is_above_high_water()) {
    ++stats_.high_water_mark_hits;
    // Trigger cleanup to get below low water mark.
    force_cleanup(config_.low_water_mark);
  }

  if (pending_.count(sequence) != 0) {
    return false;  // Already tracking this sequence
  }

  const auto now = now_fn_();
  const auto rto = current_rto_;
  PendingPacket pkt{
      .sequence = sequence,
      .data = std::move(data),
      .first_sent = now,
      .last_sent = now,
      .next_retry = now + rto,
      .retry_count = 0,
      .priority = priority,
  };

  buffered_bytes_ += pkt.data.size();
  stats_.bytes_sent += pkt.data.size();
  ++stats_.packets_sent;
  pending_.emplace(sequence, std::move(pkt));
  return true;
}

bool RetransmitBuffer::acknowledge(std::uint64_t sequence) {
  auto it = pending_.find(sequence);
  if (it == pending_.end()) {
    return false;
  }

  const auto& pkt = it->second;
  // Only update RTT if this wasn't retransmitted (Karn's algorithm).
  if (pkt.retry_count == 0) {
    const auto now = now_fn_();
    const auto rtt_sample = std::chrono::duration_cast<std::chrono::milliseconds>(now - pkt.first_sent);
    update_rtt(rtt_sample);
  }

  buffered_bytes_ -= pkt.data.size();
  ++stats_.packets_acked;
  pending_.erase(it);
  return true;
}

void RetransmitBuffer::acknowledge_cumulative(std::uint64_t sequence) {
  auto it = pending_.begin();
  while (it != pending_.end() && it->first <= sequence) {
    const auto& pkt = it->second;
    if (pkt.retry_count == 0) {
      const auto now = now_fn_();
      const auto rtt_sample =
          std::chrono::duration_cast<std::chrono::milliseconds>(now - pkt.first_sent);
      update_rtt(rtt_sample);
    }
    buffered_bytes_ -= pkt.data.size();
    ++stats_.packets_acked;
    it = pending_.erase(it);
  }
}

std::vector<const PendingPacket*> RetransmitBuffer::get_packets_to_retransmit() {
  std::vector<const PendingPacket*> result;
  const auto now = now_fn_();
  for (const auto& [seq, pkt] : pending_) {
    if (now >= pkt.next_retry) {
      result.push_back(&pkt);
    }
  }
  return result;
}

bool RetransmitBuffer::mark_retransmitted(std::uint64_t sequence) {
  auto it = pending_.find(sequence);
  if (it == pending_.end()) {
    return false;
  }

  auto& pkt = it->second;
  ++pkt.retry_count;
  if (pkt.retry_count > config_.max_retries) {
    return false;  // Exceeded max retries
  }

  // Calculate backoff: RTO * backoff_factor^retry_count
  const auto rto_ms = static_cast<double>(current_rto_.count());
  const auto backoff = static_cast<std::int64_t>(
      rto_ms * std::pow(config_.backoff_factor, static_cast<double>(pkt.retry_count)));
  const auto capped_backoff =
      std::min<std::int64_t>(backoff, config_.max_rto.count());

  const auto now = now_fn_();
  pkt.last_sent = now;
  pkt.next_retry = now + std::chrono::milliseconds(capped_backoff);

  stats_.bytes_retransmitted += pkt.data.size();
  ++stats_.packets_retransmitted;
  return true;
}

void RetransmitBuffer::drop_packet(std::uint64_t sequence) {
  auto it = pending_.find(sequence);
  if (it == pending_.end()) {
    return;
  }
  buffered_bytes_ -= it->second.data.size();
  ++stats_.packets_dropped;
  pending_.erase(it);
}

void RetransmitBuffer::update_rtt(std::chrono::milliseconds sample) {
  if (!rtt_initialized_) {
    // First sample: initialize directly (RFC 6298 section 2.2)
    estimated_rtt_ = sample;
    rtt_variance_ = sample / 2;
    rtt_initialized_ = true;
  } else {
    // Subsequent samples: EWMA update (RFC 6298 section 2.3)
    // RTTVAR <- (1 - beta) * RTTVAR + beta * |SRTT - R'|
    // SRTT <- (1 - alpha) * SRTT + alpha * R'
    const auto diff = static_cast<double>(std::abs(estimated_rtt_.count() - sample.count()));
    const auto var_count = static_cast<double>(rtt_variance_.count());
    const auto est_count = static_cast<double>(estimated_rtt_.count());
    const auto samp_count = static_cast<double>(sample.count());
    rtt_variance_ = std::chrono::milliseconds(
        static_cast<std::int64_t>((1.0 - config_.rtt_beta) * var_count +
                                   config_.rtt_beta * diff));
    estimated_rtt_ = std::chrono::milliseconds(
        static_cast<std::int64_t>((1.0 - config_.rtt_alpha) * est_count +
                                   config_.rtt_alpha * samp_count));
  }
  current_rto_ = calculate_rto();
}

std::chrono::milliseconds RetransmitBuffer::calculate_rto() const {
  // RTO = SRTT + max(G, K * RTTVAR) where G is clock granularity, K = 4
  // We ignore G (assume fine-grained clock) and use K = 4.
  const auto rto = estimated_rtt_ + 4 * rtt_variance_;
  const auto clamped =
      std::clamp(rto.count(), config_.min_rto.count(), config_.max_rto.count());
  return std::chrono::milliseconds(clamped);
}

bool RetransmitBuffer::make_room(std::size_t bytes_needed) {
  if (pending_.empty()) {
    return false;
  }

  // Apply drop policy.
  switch (config_.drop_policy) {
    case DropPolicy::kNewest:
      // Don't make room - reject the new packet.
      return false;

    case DropPolicy::kOldest: {
      // Drop oldest packets (lowest sequence numbers) until we have room.
      while (!pending_.empty() && buffered_bytes_ + bytes_needed > config_.max_buffer_bytes) {
        auto it = pending_.begin();
        buffered_bytes_ -= it->second.data.size();
        ++stats_.packets_dropped_buffer_full;
        ++stats_.packets_dropped;
        pending_.erase(it);
      }
      return buffered_bytes_ + bytes_needed <= config_.max_buffer_bytes;
    }

    case DropPolicy::kLowPriority: {
      // Drop low-priority packets first.
      // First pass: drop kLow priority.
      for (auto it = pending_.begin(); it != pending_.end();) {
        if (buffered_bytes_ + bytes_needed <= config_.max_buffer_bytes) {
          return true;
        }
        if (it->second.priority == PacketPriority::kLow) {
          buffered_bytes_ -= it->second.data.size();
          ++stats_.packets_dropped_buffer_full;
          ++stats_.packets_dropped;
          it = pending_.erase(it);
        } else {
          ++it;
        }
      }

      // Second pass: drop kNormal priority.
      for (auto it = pending_.begin(); it != pending_.end();) {
        if (buffered_bytes_ + bytes_needed <= config_.max_buffer_bytes) {
          return true;
        }
        if (it->second.priority == PacketPriority::kNormal) {
          buffered_bytes_ -= it->second.data.size();
          ++stats_.packets_dropped_buffer_full;
          ++stats_.packets_dropped;
          it = pending_.erase(it);
        } else {
          ++it;
        }
      }

      // Third pass: drop kHigh priority (but not kCritical).
      for (auto it = pending_.begin(); it != pending_.end();) {
        if (buffered_bytes_ + bytes_needed <= config_.max_buffer_bytes) {
          return true;
        }
        if (it->second.priority == PacketPriority::kHigh) {
          buffered_bytes_ -= it->second.data.size();
          ++stats_.packets_dropped_buffer_full;
          ++stats_.packets_dropped;
          it = pending_.erase(it);
        } else {
          ++it;
        }
      }

      // Cannot drop kCritical packets.
      return buffered_bytes_ + bytes_needed <= config_.max_buffer_bytes;
    }
  }

  return false;
}

bool RetransmitBuffer::check_rate_limit() {
  if (!config_.enable_burst_protection || config_.max_insert_rate == 0) {
    return true;
  }

  const auto now = now_fn_();
  const auto window_duration = std::chrono::duration_cast<std::chrono::milliseconds>(
      now - rate_limit_window_start_);

  // Reset window every second.
  if (window_duration >= std::chrono::seconds(1)) {
    rate_limit_window_start_ = now;
    inserts_in_window_ = 0;
  }

  // Check if we're within rate limit.
  if (inserts_in_window_ >= config_.max_insert_rate) {
    return false;
  }

  ++inserts_in_window_;
  return true;
}

std::size_t RetransmitBuffer::force_cleanup(std::size_t target_bytes) {
  ++stats_.cleanup_invocations;

  std::size_t dropped = 0;

  // First, drop packets that have exceeded max retries.
  for (auto it = pending_.begin(); it != pending_.end();) {
    if (buffered_bytes_ <= target_bytes) {
      break;
    }
    if (it->second.retry_count > config_.max_retries) {
      buffered_bytes_ -= it->second.data.size();
      ++stats_.packets_dropped_max_retries;
      ++stats_.packets_dropped;
      ++dropped;
      it = pending_.erase(it);
    } else {
      ++it;
    }
  }

  // Then use normal drop policy.
  if (buffered_bytes_ > target_bytes) {
    const auto bytes_to_free = buffered_bytes_ - target_bytes;
    if (make_room(bytes_to_free)) {
      // Count additional drops.
      // Note: make_room already updates stats.
    }
  }

  return dropped;
}

}  // namespace veil::mux
