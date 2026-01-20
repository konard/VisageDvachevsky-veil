#include "common/protocol_wrapper/websocket_wrapper.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

using namespace veil::protocol_wrapper;

// Test basic wrap and unwrap without masking.
TEST(WebSocketWrapperTest, WrapUnwrapNoMask) {
  std::vector<std::uint8_t> payload = {0x01, 0x02, 0x03, 0x04, 0x05};

  // Wrap without masking (server-to-client).
  auto wrapped = WebSocketWrapper::wrap(payload, false);

  // Verify wrapped is larger than original.
  EXPECT_GT(wrapped.size(), payload.size());

  // Unwrap should return original payload.
  auto unwrapped = WebSocketWrapper::unwrap(wrapped);
  ASSERT_TRUE(unwrapped.has_value());
  EXPECT_EQ(*unwrapped, payload);
}

// Test wrap and unwrap with masking (client-to-server).
TEST(WebSocketWrapperTest, WrapUnwrapWithMask) {
  std::vector<std::uint8_t> payload = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

  // Wrap with masking (client-to-server).
  auto wrapped = WebSocketWrapper::wrap(payload, true);

  // Verify wrapped is larger (includes 4-byte masking key).
  EXPECT_GE(wrapped.size(), payload.size() + 6);  // 2 bytes header + 4 bytes mask

  // Unwrap should return original payload.
  auto unwrapped = WebSocketWrapper::unwrap(wrapped);
  ASSERT_TRUE(unwrapped.has_value());
  EXPECT_EQ(*unwrapped, payload);
}

// Test small payload (< 126 bytes).
TEST(WebSocketWrapperTest, SmallPayload) {
  std::vector<std::uint8_t> payload(100, 0x42);

  auto wrapped = WebSocketWrapper::wrap(payload, false);
  auto unwrapped = WebSocketWrapper::unwrap(wrapped);

  ASSERT_TRUE(unwrapped.has_value());
  EXPECT_EQ(*unwrapped, payload);
}

// Test medium payload (126-65535 bytes).
TEST(WebSocketWrapperTest, MediumPayload) {
  std::vector<std::uint8_t> payload(1000, 0x99);

  auto wrapped = WebSocketWrapper::wrap(payload, false);
  auto unwrapped = WebSocketWrapper::unwrap(wrapped);

  ASSERT_TRUE(unwrapped.has_value());
  EXPECT_EQ(*unwrapped, payload);
}

// Test large payload (> 65535 bytes).
TEST(WebSocketWrapperTest, LargePayload) {
  std::vector<std::uint8_t> payload(100000, 0x7F);

  auto wrapped = WebSocketWrapper::wrap(payload, false);
  auto unwrapped = WebSocketWrapper::unwrap(wrapped);

  ASSERT_TRUE(unwrapped.has_value());
  EXPECT_EQ(*unwrapped, payload);
}

// Test empty payload.
TEST(WebSocketWrapperTest, EmptyPayload) {
  std::vector<std::uint8_t> payload;

  auto wrapped = WebSocketWrapper::wrap(payload, false);
  auto unwrapped = WebSocketWrapper::unwrap(wrapped);

  ASSERT_TRUE(unwrapped.has_value());
  EXPECT_EQ(unwrapped->size(), 0);
}

// Test parse_header function.
TEST(WebSocketWrapperTest, ParseHeader) {
  std::vector<std::uint8_t> payload = {0x01, 0x02, 0x03};
  auto wrapped = WebSocketWrapper::wrap(payload, false);

  auto header_result = WebSocketWrapper::parse_header(wrapped);
  ASSERT_TRUE(header_result.has_value());

  const auto& [header, offset] = *header_result;

  // Verify header fields.
  EXPECT_TRUE(header.fin);
  EXPECT_FALSE(header.rsv1);
  EXPECT_FALSE(header.rsv2);
  EXPECT_FALSE(header.rsv3);
  EXPECT_EQ(header.opcode, WebSocketOpcode::kBinary);
  EXPECT_FALSE(header.mask);
  EXPECT_EQ(header.payload_len, payload.size());

  // Verify payload starts at correct offset.
  EXPECT_EQ(offset, 2);  // 2-byte header for small payload, no mask
}

// Test parse_header with masking.
TEST(WebSocketWrapperTest, ParseHeaderWithMask) {
  std::vector<std::uint8_t> payload = {0x01, 0x02, 0x03};
  auto wrapped = WebSocketWrapper::wrap(payload, true);

  auto header_result = WebSocketWrapper::parse_header(wrapped);
  ASSERT_TRUE(header_result.has_value());

  const auto& [header, offset] = *header_result;

  EXPECT_TRUE(header.fin);
  EXPECT_EQ(header.opcode, WebSocketOpcode::kBinary);
  EXPECT_TRUE(header.mask);
  EXPECT_EQ(header.payload_len, payload.size());
  EXPECT_NE(header.masking_key, 0);  // Should have non-zero masking key

  // Verify payload starts after header + masking key.
  EXPECT_EQ(offset, 6);  // 2-byte header + 4-byte masking key
}

// Test apply_mask function.
TEST(WebSocketWrapperTest, ApplyMask) {
  std::vector<std::uint8_t> data = {0x01, 0x02, 0x03, 0x04};
  std::uint32_t masking_key = 0x12345678;

  auto original_data = data;

  // Apply mask.
  WebSocketWrapper::apply_mask(data, masking_key);

  // Data should be different after masking.
  EXPECT_NE(data, original_data);

  // Apply mask again should restore original.
  WebSocketWrapper::apply_mask(data, masking_key);
  EXPECT_EQ(data, original_data);
}

// Test build_header function.
TEST(WebSocketWrapperTest, BuildHeader) {
  WebSocketFrameHeader header;
  header.fin = true;
  header.opcode = WebSocketOpcode::kBinary;
  header.mask = false;
  header.payload_len = 100;

  auto header_bytes = WebSocketWrapper::build_header(header);

  // Small payload (< 126) should have 2-byte header.
  EXPECT_EQ(header_bytes.size(), 2);

  // First byte: FIN=1, RSV=0, Opcode=2.
  EXPECT_EQ(header_bytes[0], 0x82);  // 10000010

  // Second byte: MASK=0, Payload len=100.
  EXPECT_EQ(header_bytes[1], 100);
}

// Test build_header with masking.
TEST(WebSocketWrapperTest, BuildHeaderWithMask) {
  WebSocketFrameHeader header;
  header.fin = true;
  header.opcode = WebSocketOpcode::kBinary;
  header.mask = true;
  header.masking_key = 0xAABBCCDD;
  header.payload_len = 50;

  auto header_bytes = WebSocketWrapper::build_header(header);

  // Should have 2-byte header + 4-byte masking key.
  EXPECT_EQ(header_bytes.size(), 6);

  // First byte: FIN=1, RSV=0, Opcode=2.
  EXPECT_EQ(header_bytes[0], 0x82);

  // Second byte: MASK=1, Payload len=50.
  EXPECT_EQ(header_bytes[1], 0x80 | 50);

  // Masking key bytes.
  EXPECT_EQ(header_bytes[2], 0xAA);
  EXPECT_EQ(header_bytes[3], 0xBB);
  EXPECT_EQ(header_bytes[4], 0xCC);
  EXPECT_EQ(header_bytes[5], 0xDD);
}

// Test build_header with extended 16-bit length.
TEST(WebSocketWrapperTest, BuildHeaderExtended16) {
  WebSocketFrameHeader header;
  header.fin = true;
  header.opcode = WebSocketOpcode::kBinary;
  header.mask = false;
  header.payload_len = 1000;  // > 125, requires 16-bit length

  auto header_bytes = WebSocketWrapper::build_header(header);

  // Should have 2-byte header + 2-byte extended length.
  EXPECT_EQ(header_bytes.size(), 4);

  // Second byte should be 126 (indicator for 16-bit length).
  EXPECT_EQ(header_bytes[1], 126);

  // Extended length (big-endian).
  EXPECT_EQ(header_bytes[2], 0x03);  // 1000 >> 8
  EXPECT_EQ(header_bytes[3], 0xE8);  // 1000 & 0xFF
}

// Test build_header with extended 64-bit length.
TEST(WebSocketWrapperTest, BuildHeaderExtended64) {
  WebSocketFrameHeader header;
  header.fin = true;
  header.opcode = WebSocketOpcode::kBinary;
  header.mask = false;
  header.payload_len = 100000;  // > 65535, requires 64-bit length

  auto header_bytes = WebSocketWrapper::build_header(header);

  // Should have 2-byte header + 8-byte extended length.
  EXPECT_EQ(header_bytes.size(), 10);

  // Second byte should be 127 (indicator for 64-bit length).
  EXPECT_EQ(header_bytes[1], 127);
}

// Test invalid frame (too short).
TEST(WebSocketWrapperTest, UnwrapInvalidFrameTooShort) {
  std::vector<std::uint8_t> invalid_frame = {0x82};  // Only 1 byte

  auto unwrapped = WebSocketWrapper::unwrap(invalid_frame);
  EXPECT_FALSE(unwrapped.has_value());
}

// Test invalid frame (incomplete payload).
TEST(WebSocketWrapperTest, UnwrapInvalidFrameIncompletePayload) {
  std::vector<std::uint8_t> invalid_frame = {
      0x82,  // FIN=1, Opcode=Binary
      0x05,  // MASK=0, Payload len=5
      0x01, 0x02  // Only 2 bytes of payload (expected 5)
  };

  auto unwrapped = WebSocketWrapper::unwrap(invalid_frame);
  EXPECT_FALSE(unwrapped.has_value());
}

// Test generate_masking_key produces non-zero keys.
TEST(WebSocketWrapperTest, GenerateMaskingKey) {
  auto key1 = WebSocketWrapper::generate_masking_key();
  auto key2 = WebSocketWrapper::generate_masking_key();

  // Keys should be different (very high probability).
  EXPECT_NE(key1, key2);
}

// Test round-trip with realistic VEIL packet data.
TEST(WebSocketWrapperTest, RoundTripRealisticData) {
  // Simulate a VEIL packet.
  std::vector<std::uint8_t> veil_packet;
  veil_packet.push_back(0x56);  // Magic byte 'V'
  veil_packet.push_back(0x4C);  // Magic byte 'L'
  veil_packet.push_back(0x01);  // Version
  for (int i = 0; i < 100; ++i) {
    veil_packet.push_back(static_cast<std::uint8_t>(i % 256));
  }

  // Wrap as client-to-server.
  auto wrapped = WebSocketWrapper::wrap(veil_packet, true);

  // Verify wrapped has WebSocket header.
  EXPECT_GT(wrapped.size(), veil_packet.size());

  // Parse header.
  auto header_result = WebSocketWrapper::parse_header(wrapped);
  ASSERT_TRUE(header_result.has_value());
  EXPECT_TRUE(header_result->first.mask);
  EXPECT_EQ(header_result->first.opcode, WebSocketOpcode::kBinary);

  // Unwrap.
  auto unwrapped = WebSocketWrapper::unwrap(wrapped);
  ASSERT_TRUE(unwrapped.has_value());
  EXPECT_EQ(*unwrapped, veil_packet);
}
