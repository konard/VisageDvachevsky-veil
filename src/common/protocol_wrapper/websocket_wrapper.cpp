#include "common/protocol_wrapper/websocket_wrapper.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <limits>
#include <optional>
#include <span>
#include <vector>

#include "common/crypto/random.h"

namespace veil::protocol_wrapper {

namespace {

// Write big-endian uint16.
void write_be_u16(std::vector<std::uint8_t>& out, std::uint16_t value) {
  out.push_back(static_cast<std::uint8_t>((value >> 8) & 0xFF));
  out.push_back(static_cast<std::uint8_t>(value & 0xFF));
}

// Write big-endian uint64.
void write_be_u64(std::vector<std::uint8_t>& out, std::uint64_t value) {
  for (int i = 7; i >= 0; --i) {
    out.push_back(static_cast<std::uint8_t>((value >> (8 * i)) & 0xFF));
  }
}

// Read big-endian uint16.
std::uint16_t read_be_u16(std::span<const std::uint8_t> data, std::size_t offset) {
  return static_cast<std::uint16_t>((data[offset] << 8) | data[offset + 1]);
}

// Read big-endian uint64.
std::uint64_t read_be_u64(std::span<const std::uint8_t> data, std::size_t offset) {
  std::uint64_t value = 0;
  for (std::size_t i = 0; i < 8; ++i) {
    value = (value << 8) | data[offset + i];
  }
  return value;
}

// Read big-endian uint32.
std::uint32_t read_be_u32(std::span<const std::uint8_t> data, std::size_t offset) {
  std::uint32_t value = 0;
  for (std::size_t i = 0; i < 4; ++i) {
    value = (value << 8) | data[offset + i];
  }
  return value;
}

}  // namespace

std::vector<std::uint8_t> WebSocketWrapper::wrap(std::span<const std::uint8_t> data,
                                                   bool client_to_server) {
  WebSocketFrameHeader header;
  header.fin = true;
  header.opcode = WebSocketOpcode::kBinary;
  header.mask = client_to_server;
  header.payload_len = data.size();

  if (client_to_server) {
    header.masking_key = generate_masking_key();
  }

  auto result = build_header(header);

  // Add payload.
  if (header.mask) {
    // Apply masking.
    std::vector<std::uint8_t> masked_payload(data.begin(), data.end());
    apply_mask(masked_payload, header.masking_key);
    result.insert(result.end(), masked_payload.begin(), masked_payload.end());
  } else {
    // No masking.
    result.insert(result.end(), data.begin(), data.end());
  }

  return result;
}

std::optional<std::vector<std::uint8_t>> WebSocketWrapper::unwrap(
    std::span<const std::uint8_t> frame) {
  auto header_result = parse_header(frame);
  if (!header_result.has_value()) {
    return std::nullopt;
  }

  const auto& [header, payload_offset] = *header_result;

  // Check that frame has complete payload.
  if (frame.size() < payload_offset + header.payload_len) {
    return std::nullopt;
  }

  // Extract payload.
  std::vector<std::uint8_t> payload(
      frame.begin() + static_cast<std::ptrdiff_t>(payload_offset),
      frame.begin() + static_cast<std::ptrdiff_t>(payload_offset + header.payload_len));

  // Unmask if needed.
  if (header.mask) {
    apply_mask(payload, header.masking_key);
  }

  return payload;
}

std::optional<std::pair<WebSocketFrameHeader, std::size_t>> WebSocketWrapper::parse_header(
    std::span<const std::uint8_t> data) {
  // Minimum header size is 2 bytes.
  if (data.size() < 2) {
    return std::nullopt;
  }

  WebSocketFrameHeader header;

  // First byte: FIN, RSV1-3, Opcode.
  const std::uint8_t byte0 = data[0];
  header.fin = (byte0 & 0x80) != 0;
  header.rsv1 = (byte0 & 0x40) != 0;
  header.rsv2 = (byte0 & 0x20) != 0;
  header.rsv3 = (byte0 & 0x10) != 0;
  header.opcode = static_cast<WebSocketOpcode>(byte0 & 0x0F);

  // Second byte: MASK, Payload len (7 bits).
  const std::uint8_t byte1 = data[1];
  header.mask = (byte1 & 0x80) != 0;
  std::uint8_t payload_len_7bit = byte1 & 0x7F;

  std::size_t offset = 2;

  // Determine actual payload length.
  if (payload_len_7bit < 126) {
    header.payload_len = payload_len_7bit;
  } else if (payload_len_7bit == 126) {
    // 16-bit extended payload length.
    if (data.size() < offset + 2) {
      return std::nullopt;
    }
    header.payload_len = read_be_u16(data, offset);
    offset += 2;
  } else {  // payload_len_7bit == 127
    // 64-bit extended payload length.
    if (data.size() < offset + 8) {
      return std::nullopt;
    }
    header.payload_len = read_be_u64(data, offset);
    offset += 8;
  }

  // Read masking key if present.
  if (header.mask) {
    if (data.size() < offset + 4) {
      return std::nullopt;
    }
    header.masking_key = read_be_u32(data, offset);
    offset += 4;
  }

  return std::make_pair(header, offset);
}

std::vector<std::uint8_t> WebSocketWrapper::build_header(const WebSocketFrameHeader& header) {
  std::vector<std::uint8_t> result;

  // First byte: FIN, RSV1-3, Opcode.
  std::uint8_t byte0 = static_cast<std::uint8_t>(header.opcode) & 0x0F;
  if (header.fin) {
    byte0 |= 0x80;
  }
  if (header.rsv1) {
    byte0 |= 0x40;
  }
  if (header.rsv2) {
    byte0 |= 0x20;
  }
  if (header.rsv3) {
    byte0 |= 0x10;
  }
  result.push_back(byte0);

  // Second byte: MASK, Payload len.
  std::uint8_t byte1 = 0;
  if (header.mask) {
    byte1 |= 0x80;
  }

  if (header.payload_len < 126) {
    byte1 |= static_cast<std::uint8_t>(header.payload_len);
    result.push_back(byte1);
  } else if (header.payload_len <= 0xFFFF) {
    byte1 |= 126;
    result.push_back(byte1);
    write_be_u16(result, static_cast<std::uint16_t>(header.payload_len));
  } else {
    byte1 |= 127;
    result.push_back(byte1);
    write_be_u64(result, header.payload_len);
  }

  // Add masking key if needed.
  if (header.mask) {
    for (int i = 3; i >= 0; --i) {
      result.push_back(static_cast<std::uint8_t>((header.masking_key >> (8 * i)) & 0xFF));
    }
  }

  return result;
}

void WebSocketWrapper::apply_mask(std::span<std::uint8_t> data, std::uint32_t masking_key) {
  // Extract masking key bytes.
  std::array<std::uint8_t, 4> mask_bytes;
  for (std::size_t i = 0; i < 4; ++i) {
    mask_bytes[i] = static_cast<std::uint8_t>((masking_key >> (8 * (3 - i))) & 0xFF);
  }

  // Apply XOR masking.
  for (std::size_t i = 0; i < data.size(); ++i) {
    data[i] ^= mask_bytes[i % 4];
  }
}

std::uint32_t WebSocketWrapper::generate_masking_key() {
  auto random_bytes = crypto::random_bytes(4);
  std::uint32_t key = 0;
  for (std::size_t i = 0; i < 4; ++i) {
    key = (key << 8) | random_bytes[i];
  }
  return key;
}

}  // namespace veil::protocol_wrapper
