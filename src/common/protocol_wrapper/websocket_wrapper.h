#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace veil::protocol_wrapper {

// WebSocket frame opcodes (RFC 6455).
enum class WebSocketOpcode : std::uint8_t {
  kContinuation = 0x0,
  kText = 0x1,
  kBinary = 0x2,
  kClose = 0x8,
  kPing = 0x9,
  kPong = 0xA,
};

// WebSocket frame header flags.
struct WebSocketFrameHeader {
  bool fin{true};              // Final fragment flag
  bool rsv1{false};            // Reserved bit 1 (must be 0 unless extension negotiated)
  bool rsv2{false};            // Reserved bit 2 (must be 0 unless extension negotiated)
  bool rsv3{false};            // Reserved bit 3 (must be 0 unless extension negotiated)
  WebSocketOpcode opcode{WebSocketOpcode::kBinary};
  bool mask{false};            // Masking flag (true for client->server)
  std::uint64_t payload_len{0};  // Payload length
  std::uint32_t masking_key{0};  // Masking key (if mask=true)
};

// WebSocket frame structure.
struct WebSocketFrame {
  WebSocketFrameHeader header;
  std::vector<std::uint8_t> payload;
};

// WebSocket protocol wrapper for DPI evasion.
// Wraps VEIL packets in WebSocket binary frames to mimic legitimate WebSocket traffic.
//
// Usage:
//   auto wrapped = wrap_in_websocket_frame(veil_packet, true);  // true = client-to-server
//   auto unwrapped = unwrap_websocket_frame(wrapped);
//
// WebSocket frame format (RFC 6455):
//   0                   1                   2                   3
//   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//  +-+-+-+-+-------+-+-------------+-------------------------------+
//  |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
//  |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
//  |N|V|V|V|       |S|             |   (if payload len==126/127)   |
//  | |1|2|3|       |K|             |                               |
//  +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
//  |     Extended payload length continued, if payload len == 127  |
//  + - - - - - - - - - - - - - - - +-------------------------------+
//  |                               |Masking-key, if MASK set to 1  |
//  +-------------------------------+-------------------------------+
//  | Masking-key (continued)       |          Payload Data         |
//  +-------------------------------- - - - - - - - - - - - - - - - +
//  :                     Payload Data continued ...                :
//  + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
//  |                     Payload Data continued ...                |
//  +---------------------------------------------------------------+

class WebSocketWrapper {
 public:
  // Wrap data in a WebSocket binary frame.
  // client_to_server: if true, applies masking (client->server frames must be masked)
  static std::vector<std::uint8_t> wrap(std::span<const std::uint8_t> data,
                                         bool client_to_server = false);

  // Unwrap a WebSocket frame and return the payload.
  // Returns std::nullopt if the frame is invalid or incomplete.
  static std::optional<std::vector<std::uint8_t>> unwrap(std::span<const std::uint8_t> frame);

  // Parse WebSocket frame header.
  // Returns header and the offset where payload starts, or std::nullopt if invalid.
  static std::optional<std::pair<WebSocketFrameHeader, std::size_t>> parse_header(
      std::span<const std::uint8_t> data);

  // Build WebSocket frame header bytes.
  static std::vector<std::uint8_t> build_header(const WebSocketFrameHeader& header);

  // Apply XOR masking to payload (RFC 6455 section 5.3).
  static void apply_mask(std::span<std::uint8_t> data, std::uint32_t masking_key);

  // Generate a random masking key.
  static std::uint32_t generate_masking_key();
};

}  // namespace veil::protocol_wrapper
