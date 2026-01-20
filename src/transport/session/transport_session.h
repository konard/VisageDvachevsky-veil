#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <vector>

#include "common/crypto/crypto_engine.h"
#include "common/handshake/handshake_processor.h"
#include "common/session/replay_window.h"
#include "common/session/session_rotator.h"
#include "common/utils/thread_checker.h"
#include "transport/mux/ack_bitmap.h"
#include "transport/mux/fragment_reassembly.h"
#include "transport/mux/mux_codec.h"
#include "transport/mux/reorder_buffer.h"
#include "transport/mux/retransmit_buffer.h"

namespace veil::transport {

// Configuration for transport session behavior.
struct TransportSessionConfig {
  // MTU for outgoing packets (excluding IP/UDP overhead).
  std::size_t mtu{1400};
  // Maximum fragment size (should be <= mtu - header overhead).
  std::size_t max_fragment_size{1350};
  // Replay window size in bits.
  std::size_t replay_window_size{1024};
  // Session rotation interval.
  std::chrono::seconds session_rotation_interval{30};
  // Packets before forced session rotation.
  std::uint64_t session_rotation_packets{1000000};
  // Reorder buffer max bytes.
  std::size_t reorder_buffer_size{1 << 20};
  // Fragment reassembly max bytes per message.
  std::size_t fragment_buffer_size{1 << 20};
  // Retransmit configuration.
  mux::RetransmitConfig retransmit_config{};
};

// Statistics for observability.
struct TransportStats {
  std::uint64_t packets_sent{0};
  std::uint64_t packets_received{0};
  std::uint64_t bytes_sent{0};
  std::uint64_t bytes_received{0};
  std::uint64_t packets_dropped_replay{0};
  std::uint64_t packets_dropped_decrypt{0};
  std::uint64_t packets_dropped_late{0};
  std::uint64_t fragments_sent{0};
  std::uint64_t fragments_received{0};
  std::uint64_t messages_reassembled{0};
  std::uint64_t retransmits{0};
  std::uint64_t session_rotations{0};
};

/**
 * Encrypted transport session built from handshake result.
 * Handles encryption/decryption, replay protection, fragmentation,
 * retransmission, and session rotation.
 *
 * Thread Safety:
 *   This class is NOT thread-safe. All methods must be called from a single
 *   thread (typically the event loop thread that owns this session).
 *   The session contains internal state (sequence counters, replay window,
 *   retransmit buffer) that is not protected by locks.
 *
 *   If you need to access the session from multiple threads, external
 *   synchronization is required.
 *
 * @see docs/thread_model.md for the VEIL threading model documentation.
 */
class TransportSession {
 public:
  using Clock = std::chrono::steady_clock;
  using TimePoint = Clock::time_point;

  // Create a session from a completed handshake.
  TransportSession(const handshake::HandshakeSession& handshake_session,
                   TransportSessionConfig config = {},
                   std::function<TimePoint()> now_fn = Clock::now);

  /// SECURITY: Destructor clears all session key material
  ~TransportSession();

  // Disable copy (contains sensitive data)
  TransportSession(const TransportSession&) = delete;
  TransportSession& operator=(const TransportSession&) = delete;

  // Enable move
  TransportSession(TransportSession&&) = default;
  TransportSession& operator=(TransportSession&&) = default;

  // Encrypt and serialize data for transmission.
  // Returns encrypted packet bytes ready to send.
  // If data exceeds MTU, it will be fragmented into multiple packets.
  std::vector<std::vector<std::uint8_t>> encrypt_data(std::span<const std::uint8_t> plaintext,
                                                       std::uint64_t stream_id = 0, bool fin = false);

  // Decrypt and process a received packet.
  // Returns decrypted mux frames if successful.
  // Performs replay check and decryption.
  std::optional<std::vector<mux::MuxFrame>> decrypt_packet(std::span<const std::uint8_t> ciphertext);

  // Get packets that need retransmission.
  std::vector<std::vector<std::uint8_t>> get_retransmit_packets();

  // Process an ACK frame (acknowledges sent packets).
  void process_ack(const mux::AckFrame& ack);

  // Generate an ACK frame for received packets on a stream.
  mux::AckFrame generate_ack(std::uint64_t stream_id);

  // Check if session should rotate (time or packet count threshold).
  bool should_rotate_session();

  /// Perform session rotation.
  /// IMPORTANT: This ONLY rotates the session_id for protocol-level management.
  /// The send_sequence_ counter is NOT reset - it continues monotonically.
  /// This is critical for nonce uniqueness: nonce = derive_nonce(base_nonce, send_sequence_).
  /// See Issue #3 for detailed security analysis.
  void rotate_session();

  // Get current session ID.
  std::uint64_t session_id() const { return current_session_id_; }

  // Get current send sequence number.
  std::uint64_t send_sequence() const { return send_sequence_; }

  // Get statistics.
  const TransportStats& stats() const { return stats_; }

  // Get retransmit buffer statistics.
  const mux::RetransmitStats& retransmit_stats() const { return retransmit_buffer_.stats(); }

 private:
  // Build an encrypted packet from mux frame.
  std::vector<std::uint8_t> build_encrypted_packet(const mux::MuxFrame& frame);

  // Fragment large data into multiple frames.
  std::vector<mux::MuxFrame> fragment_data(std::span<const std::uint8_t> data, std::uint64_t stream_id,
                                            bool fin);

  TransportSessionConfig config_;
  std::function<TimePoint()> now_fn_;

  // Crypto keys from handshake.
  crypto::SessionKeys keys_;
  std::uint64_t current_session_id_;

  // DPI resistance: Keys for obfuscating sequence numbers (Issue #21).
  // These are derived from session keys to prevent traffic analysis.
  std::array<std::uint8_t, crypto::kAeadKeyLen> send_seq_obfuscation_key_;
  std::array<std::uint8_t, crypto::kAeadKeyLen> recv_seq_obfuscation_key_;

  // Sequence counters.
  // SECURITY-CRITICAL: send_sequence_ is used for nonce derivation.
  // It MUST NEVER be reset - it continues monotonically across session rotations.
  // nonce = derive_nonce(base_nonce, send_sequence_)
  // Resetting would cause nonce reuse, completely breaking ChaCha20-Poly1305 security.
  std::uint64_t send_sequence_{0};
  std::uint64_t recv_sequence_max_{0};

  // Replay protection.
  session::ReplayWindow replay_window_;

  // Session rotation.
  session::SessionRotator session_rotator_;
  std::uint64_t packets_since_rotation_{0};

  // Multiplexing state.
  mux::AckBitmap recv_ack_bitmap_;
  mux::ReorderBuffer reorder_buffer_;
  mux::FragmentReassembly fragment_reassembly_;
  mux::RetransmitBuffer retransmit_buffer_;

  // Message ID counter for fragmentation.
  std::uint64_t message_id_counter_{0};

  // Statistics.
  TransportStats stats_;

  // Thread safety: verifies single-threaded access in debug builds.
  VEIL_THREAD_CHECKER(thread_checker_);
};

}  // namespace veil::transport
