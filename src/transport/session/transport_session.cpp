#include "transport/session/transport_session.h"

#include <sodium.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include "common/crypto/crypto_engine.h"
#include "common/crypto/random.h"
#include "common/logging/logger.h"

namespace veil::transport {

TransportSession::TransportSession(const handshake::HandshakeSession& handshake_session,
                                   TransportSessionConfig config, std::function<TimePoint()> now_fn)
    : config_(config),
      now_fn_(std::move(now_fn)),
      keys_(handshake_session.keys),
      current_session_id_(handshake_session.session_id),
      replay_window_(config_.replay_window_size),
      session_rotator_(config_.session_rotation_interval, config_.session_rotation_packets),
      reorder_buffer_(0, config_.reorder_buffer_size),
      fragment_reassembly_(config_.fragment_buffer_size),
      retransmit_buffer_(config_.retransmit_config, now_fn_) {
  LOG_DEBUG("TransportSession created with session_id={}", current_session_id_);
}

TransportSession::~TransportSession() {
  // SECURITY: Clear all session key material on destruction
  sodium_memzero(keys_.send_key.data(), keys_.send_key.size());
  sodium_memzero(keys_.recv_key.data(), keys_.recv_key.size());
  sodium_memzero(keys_.send_nonce.data(), keys_.send_nonce.size());
  sodium_memzero(keys_.recv_nonce.data(), keys_.recv_nonce.size());
  LOG_DEBUG("TransportSession destroyed, keys cleared");
}

std::vector<std::vector<std::uint8_t>> TransportSession::encrypt_data(
    std::span<const std::uint8_t> plaintext, std::uint64_t stream_id, bool fin) {
  VEIL_DCHECK_THREAD(thread_checker_);

  std::vector<std::vector<std::uint8_t>> result;

  // Fragment data if necessary.
  auto frames = fragment_data(plaintext, stream_id, fin);

  for (auto& frame : frames) {
    auto encrypted = build_encrypted_packet(frame);

    // Store in retransmit buffer.
    if (retransmit_buffer_.has_capacity(encrypted.size())) {
      retransmit_buffer_.insert(send_sequence_ - 1, encrypted);
    }

    ++stats_.packets_sent;
    stats_.bytes_sent += encrypted.size();
    if (frame.kind == mux::FrameKind::kData) {
      ++stats_.fragments_sent;
    }

    result.push_back(std::move(encrypted));
    ++packets_since_rotation_;
  }

  return result;
}

std::optional<std::vector<mux::MuxFrame>> TransportSession::decrypt_packet(
    std::span<const std::uint8_t> ciphertext) {
  VEIL_DCHECK_THREAD(thread_checker_);

  // Minimum packet size: nonce (8 bytes for sequence) + tag (16 bytes) + header (1 byte minimum)
  constexpr std::size_t kMinPacketSize = 8 + 16 + 1;
  if (ciphertext.size() < kMinPacketSize) {
    LOG_DEBUG("Packet too small: {} bytes", ciphertext.size());
    ++stats_.packets_dropped_decrypt;
    return std::nullopt;
  }

  // Extract sequence from first 8 bytes (used as part of nonce).
  std::uint64_t sequence = 0;
  for (int i = 0; i < 8; ++i) {
    sequence = (sequence << 8) | ciphertext[static_cast<std::size_t>(i)];
  }

  // Replay check.
  if (!replay_window_.mark_and_check(sequence)) {
    LOG_DEBUG("Packet replay detected: sequence={}", sequence);
    ++stats_.packets_dropped_replay;
    return std::nullopt;
  }

  // Derive nonce from sequence.
  const auto nonce = crypto::derive_nonce(keys_.recv_nonce, sequence);

  // Decrypt (skip sequence prefix).
  auto ciphertext_body = ciphertext.subspan(8);
  auto decrypted = crypto::aead_decrypt(keys_.recv_key, nonce, {}, ciphertext_body);
  if (!decrypted) {
    LOG_DEBUG("Decryption failed for sequence={}", sequence);
    ++stats_.packets_dropped_decrypt;
    return std::nullopt;
  }

  ++stats_.packets_received;
  stats_.bytes_received += ciphertext.size();

  // Parse mux frames from decrypted data.
  std::vector<mux::MuxFrame> frames;
  auto frame = mux::MuxCodec::decode(*decrypted);
  if (frame) {
    frames.push_back(std::move(*frame));

    if (frame->kind == mux::FrameKind::kData) {
      ++stats_.fragments_received;
      recv_ack_bitmap_.ack(sequence);
    }
  }

  if (sequence > recv_sequence_max_) {
    recv_sequence_max_ = sequence;
  }

  return frames;
}

std::vector<std::vector<std::uint8_t>> TransportSession::get_retransmit_packets() {
  VEIL_DCHECK_THREAD(thread_checker_);

  std::vector<std::vector<std::uint8_t>> result;
  auto to_retransmit = retransmit_buffer_.get_packets_to_retransmit();

  for (const auto* pkt : to_retransmit) {
    if (retransmit_buffer_.mark_retransmitted(pkt->sequence)) {
      result.push_back(pkt->data);
      ++stats_.retransmits;
    } else {
      // Exceeded max retries, drop packet.
      retransmit_buffer_.drop_packet(pkt->sequence);
    }
  }

  return result;
}

void TransportSession::process_ack(const mux::AckFrame& ack) {
  VEIL_DCHECK_THREAD(thread_checker_);

  // Cumulative ACK.
  retransmit_buffer_.acknowledge_cumulative(ack.ack);

  // Selective ACK from bitmap.
  for (std::uint32_t i = 0; i < 32; ++i) {
    if (((ack.bitmap >> i) & 1U) != 0U) {
      std::uint64_t seq = ack.ack - 1 - i;
      if (seq > 0) {
        retransmit_buffer_.acknowledge(seq);
      }
    }
  }
}

mux::AckFrame TransportSession::generate_ack(std::uint64_t stream_id) {
  VEIL_DCHECK_THREAD(thread_checker_);

  return mux::AckFrame{
      .stream_id = stream_id,
      .ack = recv_ack_bitmap_.head(),
      .bitmap = recv_ack_bitmap_.bitmap(),
  };
}

bool TransportSession::should_rotate_session() {
  VEIL_DCHECK_THREAD(thread_checker_);
  return session_rotator_.should_rotate(packets_since_rotation_, now_fn_());
}

void TransportSession::rotate_session() {
  VEIL_DCHECK_THREAD(thread_checker_);

  current_session_id_ = session_rotator_.rotate(now_fn_());
  packets_since_rotation_ = 0;
  ++stats_.session_rotations;

  // SECURITY NOTE: Nonce counter reset is NOT needed here.
  // The nonce for ChaCha20-Poly1305 is derived as: derive_nonce(base_nonce, send_sequence_).
  // The send_sequence_ counter is NOT reset during rotation - it continues monotonically.
  // This ensures nonce uniqueness: as long as send_sequence_ never repeats (uint64_t gives
  // 2^64 packets before overflow), we never reuse a (key, nonce) pair.
  // Session rotation only changes the session_id for protocol-level session management,
  // not for cryptographic key rotation.

  LOG_DEBUG("Session rotated to session_id={}", current_session_id_);
}

std::vector<std::uint8_t> TransportSession::build_encrypted_packet(const mux::MuxFrame& frame) {
  // Serialize the frame.
  auto plaintext = mux::MuxCodec::encode(frame);

  // Derive nonce from current send sequence.
  const auto nonce = crypto::derive_nonce(keys_.send_nonce, send_sequence_);

  // Encrypt.
  auto ciphertext = crypto::aead_encrypt(keys_.send_key, nonce, {}, plaintext);

  // Prepend sequence number (8 bytes big-endian).
  std::vector<std::uint8_t> packet;
  packet.reserve(8 + ciphertext.size());
  for (int i = 7; i >= 0; --i) {
    packet.push_back(static_cast<std::uint8_t>((send_sequence_ >> (8 * i)) & 0xFF));
  }
  packet.insert(packet.end(), ciphertext.begin(), ciphertext.end());

  ++send_sequence_;
  return packet;
}

std::vector<mux::MuxFrame> TransportSession::fragment_data(std::span<const std::uint8_t> data,
                                                            std::uint64_t stream_id, bool fin) {
  std::vector<mux::MuxFrame> frames;

  if (data.size() <= config_.max_fragment_size) {
    // No fragmentation needed.
    frames.push_back(mux::make_data_frame(
        stream_id, message_id_counter_++, fin,
        std::vector<std::uint8_t>(data.begin(), data.end())));
    return frames;
  }

  // Fragment the data.
  const std::uint64_t msg_id = message_id_counter_++;
  std::size_t offset = 0;
  std::uint64_t frag_seq = 0;

  while (offset < data.size()) {
    const std::size_t chunk_size = std::min(config_.max_fragment_size, data.size() - offset);
    const bool is_last = (offset + chunk_size >= data.size());
    const bool frag_fin = is_last && fin;

    std::vector<std::uint8_t> chunk(data.begin() + static_cast<std::ptrdiff_t>(offset),
                                     data.begin() + static_cast<std::ptrdiff_t>(offset + chunk_size));

    // For fragmented messages, we use a special encoding in the sequence field.
    // High 32 bits: message ID, Low 32 bits: fragment index.
    const std::uint64_t encoded_seq = (msg_id << 32) | frag_seq;

    frames.push_back(mux::make_data_frame(stream_id, encoded_seq, frag_fin, std::move(chunk)));

    offset += chunk_size;
    ++frag_seq;
  }

  return frames;
}

}  // namespace veil::transport
