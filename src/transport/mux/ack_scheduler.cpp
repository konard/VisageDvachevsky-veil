#include "transport/mux/ack_scheduler.h"

#include <algorithm>

namespace veil::mux {

AckScheduler::AckScheduler(AckSchedulerConfig config, std::function<TimePoint()> now_fn)
    : config_(config), now_fn_(std::move(now_fn)) {}

bool AckScheduler::on_packet_received(std::uint64_t stream_id, std::uint64_t sequence, bool fin) {
  // Find or create stream state.
  auto it = std::find_if(streams_.begin(), streams_.end(),
                         [stream_id](const auto& pair) { return pair.first == stream_id; });

  if (it == streams_.end()) {
    streams_.emplace_back(stream_id, StreamAckState{});
    it = streams_.end() - 1;
  }

  auto& state = it->second;

  // Check for gap (out-of-order).
  if (sequence > state.highest_received + 1 && state.highest_received > 0) {
    state.gap_detected = true;
    ++stats_.gaps_detected;
  }

  // Update state.
  update_bitmap(state, sequence);

  if (sequence > state.highest_received) {
    state.highest_received = sequence;
  }

  ++state.packets_since_ack;
  state.needs_ack = true;

  // Record first unacked time.
  if (state.packets_since_ack == 1) {
    state.first_unacked_time = now_fn_();
  }

  // Check if immediate ACK needed.
  if (should_send_immediate_ack(state, fin)) {
    ++stats_.acks_immediate;
    return true;
  }

  // Otherwise, delay ACK.
  ++stats_.acks_delayed;
  return false;
}

std::optional<std::uint64_t> AckScheduler::check_ack_timer() {
  const auto now = now_fn_();

  for (auto& [stream_id, state] : streams_) {
    if (!state.needs_ack) {
      continue;
    }

    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - state.first_unacked_time);

    if (elapsed >= config_.max_ack_delay) {
      return stream_id;
    }
  }

  return std::nullopt;
}

std::optional<AckFrame> AckScheduler::get_pending_ack(std::uint64_t stream_id) {
  auto it = std::find_if(streams_.begin(), streams_.end(),
                         [stream_id](const auto& pair) { return pair.first == stream_id; });

  if (it == streams_.end() || !it->second.needs_ack) {
    return std::nullopt;
  }

  const auto& state = it->second;

  AckFrame frame{
      .stream_id = stream_id,
      .ack = state.highest_received,
      .bitmap = state.received_bitmap,
  };

  return frame;
}

void AckScheduler::ack_sent(std::uint64_t stream_id) {
  auto it = std::find_if(streams_.begin(), streams_.end(),
                         [stream_id](const auto& pair) { return pair.first == stream_id; });

  if (it == streams_.end()) {
    return;
  }

  auto& state = it->second;

  // Count coalesced ACKs.
  if (state.packets_since_ack > 1) {
    stats_.acks_coalesced += state.packets_since_ack - 1;
  }

  ++stats_.acks_sent;
  state.packets_since_ack = 0;
  state.needs_ack = false;
  state.gap_detected = false;
  state.received_bitmap = 0;
}

std::optional<std::chrono::milliseconds> AckScheduler::time_until_next_ack() const {
  const auto now = now_fn_();
  std::optional<std::chrono::milliseconds> min_time;

  for (const auto& [stream_id, state] : streams_) {
    if (!state.needs_ack) {
      continue;
    }

    const auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - state.first_unacked_time);
    const auto remaining = config_.max_ack_delay - elapsed;

    if (remaining <= std::chrono::milliseconds(0)) {
      return std::chrono::milliseconds(0);
    }

    if (!min_time || remaining < *min_time) {
      min_time = remaining;
    }
  }

  return min_time;
}

void AckScheduler::reset_stream(std::uint64_t stream_id) {
  auto it = std::find_if(streams_.begin(), streams_.end(),
                         [stream_id](const auto& pair) { return pair.first == stream_id; });

  if (it != streams_.end()) {
    streams_.erase(it);
  }
}

void AckScheduler::update_bitmap(StreamAckState& state, std::uint64_t sequence) {
  // Bitmap tracks which packets in the last 32 before highest_received have been received.
  if (state.highest_received == 0) {
    state.received_bitmap = 0;
    return;
  }

  if (sequence <= state.highest_received) {
    // This is a packet before or at highest_received.
    const auto offset = state.highest_received - sequence;
    if (offset < 32) {
      state.received_bitmap |= (1U << static_cast<std::uint32_t>(offset));
    }
  } else {
    // New highest received - shift bitmap.
    const auto shift = static_cast<std::uint32_t>(sequence - state.highest_received);
    if (shift < 32) {
      state.received_bitmap <<= shift;
      state.received_bitmap |= (1U << (shift - 1));  // Mark previous highest as received.
    } else {
      state.received_bitmap = 0;
    }
  }
}

bool AckScheduler::should_send_immediate_ack(const StreamAckState& state, bool fin) const {
  // Immediate ACK for FIN packets.
  if (fin && config_.immediate_ack_on_fin) {
    return true;
  }

  // Immediate ACK for out-of-order (gap detected).
  if (state.gap_detected && config_.immediate_ack_on_gap) {
    return true;
  }

  // Immediate ACK after N packets.
  if (state.packets_since_ack >= config_.ack_every_n_packets) {
    return true;
  }

  // Immediate ACK if too many pending.
  if (config_.enable_coalescing && state.packets_since_ack >= config_.max_pending_acks) {
    return true;
  }

  return false;
}

}  // namespace veil::mux
