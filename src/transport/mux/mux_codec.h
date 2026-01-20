#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "transport/mux/frame.h"

namespace veil::mux {

// Serializes and parses MuxFrame structures for wire transmission.
// Wire format:
//   [kind: 1 byte]
//   For kData:
//     [stream_id: 8 bytes big-endian]
//     [sequence: 8 bytes big-endian]
//     [flags: 1 byte, bit 0 = FIN]
//     [payload_len: 2 bytes big-endian]
//     [payload: payload_len bytes]
//   For kAck:
//     [stream_id: 8 bytes big-endian]
//     [ack: 8 bytes big-endian]
//     [bitmap: 4 bytes big-endian]
//   For kControl:
//     [type: 1 byte]
//     [payload_len: 2 bytes big-endian]
//     [payload: payload_len bytes]
//   For kHeartbeat:
//     [timestamp: 8 bytes big-endian]
//     [sequence: 8 bytes big-endian]
//     [payload_len: 2 bytes big-endian]
//     [payload: payload_len bytes]

class MuxCodec {
 public:
  // Serialize a MuxFrame to bytes.
  static std::vector<std::uint8_t> encode(const MuxFrame& frame);

  // Parse bytes into a MuxFrame. Returns nullopt on malformed input.
  static std::optional<MuxFrame> decode(std::span<const std::uint8_t> data);

  // Returns the expected size needed to encode this frame (for pre-allocation).
  static std::size_t encoded_size(const MuxFrame& frame);

  // Minimum sizes for each frame type header (excluding payload).
  static constexpr std::size_t kDataHeaderSize = 1 + 8 + 8 + 1 + 2;    // 20 bytes
  static constexpr std::size_t kAckSize = 1 + 8 + 8 + 4;               // 21 bytes
  static constexpr std::size_t kControlHeaderSize = 1 + 1 + 2;         // 4 bytes
  static constexpr std::size_t kHeartbeatHeaderSize = 1 + 8 + 8 + 2;   // 19 bytes
  static constexpr std::size_t kMaxPayloadSize = 65535;
};

// Helper to create common frame types.
MuxFrame make_data_frame(std::uint64_t stream_id, std::uint64_t sequence, bool fin,
                         std::vector<std::uint8_t> payload);

MuxFrame make_ack_frame(std::uint64_t stream_id, std::uint64_t ack, std::uint32_t bitmap);

MuxFrame make_control_frame(std::uint8_t type, std::vector<std::uint8_t> payload);

MuxFrame make_heartbeat_frame(std::uint64_t timestamp, std::uint64_t sequence,
                               std::vector<std::uint8_t> payload = {});

}  // namespace veil::mux
