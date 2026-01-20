#include <gtest/gtest.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "common/packet/packet_builder.h"

namespace veil::tests {

TEST(PacketTests, BuildAndParseRoundTrip) {
  packet::PacketBuilder builder;
  builder.set_session_id(42).set_sequence(7).set_flags(0xAA);
  const std::vector<std::uint8_t> payload{'h', 'i'};
  builder.add_frame(packet::FrameType::kData, payload);
  builder.add_padding(8);

  const auto bytes = builder.build();
  auto parsed = packet::PacketParser::parse(bytes);
  ASSERT_TRUE(parsed.has_value());
  const auto pkt = parsed.value();
  EXPECT_EQ(pkt.session_id, 42U);
  EXPECT_EQ(pkt.sequence, 7U);
  EXPECT_EQ(pkt.flags, 0xAA);
  ASSERT_EQ(pkt.frames.size(), 2U);
  EXPECT_EQ(pkt.frames[0].type, packet::FrameType::kData);
  EXPECT_EQ(pkt.frames[0].data, payload);
  EXPECT_EQ(pkt.frames[1].type, packet::FrameType::kPadding);
}

TEST(PacketTests, RejectsInvalidMagic) {
  std::vector<std::uint8_t> bytes{0, 0};
  auto parsed = packet::PacketParser::parse(bytes);
  EXPECT_FALSE(parsed.has_value());
}

// Negative/edge case tests for packet parsing.

TEST(PacketTests, RejectsEmptyBuffer) {
  auto parsed = packet::PacketParser::parse({});
  EXPECT_FALSE(parsed.has_value());
}

TEST(PacketTests, RejectsTruncatedHeader) {
  // Magic + version = 3 bytes, but need full header (23 bytes).
  std::vector<std::uint8_t> truncated{0x56, 0x4C, 0x01};
  auto parsed = packet::PacketParser::parse(truncated);
  EXPECT_FALSE(parsed.has_value());
}

TEST(PacketTests, RejectsInvalidVersion) {
  packet::PacketBuilder builder;
  builder.set_session_id(1).set_sequence(1);
  auto bytes = builder.build();
  bytes[2] = 0xFF;  // Invalid version
  auto parsed = packet::PacketParser::parse(bytes);
  EXPECT_FALSE(parsed.has_value());
}

TEST(PacketTests, RejectsPayloadLengthMismatch) {
  packet::PacketBuilder builder;
  builder.set_session_id(1).set_sequence(1);
  std::vector<std::uint8_t> payload{1, 2, 3};
  builder.add_frame(packet::FrameType::kData, payload);
  auto bytes = builder.build();
  // Truncate the packet to break payload length validation.
  ASSERT_GT(bytes.size(), 2U);
  bytes.erase(bytes.end() - 2, bytes.end());
  auto parsed = packet::PacketParser::parse(bytes);
  EXPECT_FALSE(parsed.has_value());
}

TEST(PacketTests, RejectsTruncatedFrameHeader) {
  packet::PacketBuilder builder;
  builder.set_session_id(1).set_sequence(1);
  std::vector<std::uint8_t> payload{1, 2, 3, 4, 5};
  builder.add_frame(packet::FrameType::kData, payload);
  auto bytes = builder.build();
  // Corrupt the frame count to indicate more frames than exist.
  bytes[20] = 5;  // Frame count at offset 20
  auto parsed = packet::PacketParser::parse(bytes);
  EXPECT_FALSE(parsed.has_value());
}

TEST(PacketTests, RejectsTruncatedFrameData) {
  packet::PacketBuilder builder;
  builder.set_session_id(1).set_sequence(1);
  std::vector<std::uint8_t> payload{1, 2, 3, 4, 5};
  builder.add_frame(packet::FrameType::kData, payload);
  auto bytes = builder.build();
  // Increase the frame length field to exceed available data.
  // Frame header is at offset 23 (after packet header).
  // Frame length is at bytes[24:25] (big-endian 16-bit).
  bytes[24] = 0xFF;  // High byte of length
  auto parsed = packet::PacketParser::parse(bytes);
  EXPECT_FALSE(parsed.has_value());
}

TEST(PacketTests, ParsesLargeSessionIdAndSequence) {
  packet::PacketBuilder builder;
  builder.set_session_id(0xFFFFFFFFFFFFFFFF).set_sequence(0x123456789ABCDEF0);
  std::vector<std::uint8_t> payload{0x42};
  builder.add_frame(packet::FrameType::kData, payload);
  auto bytes = builder.build();
  auto parsed = packet::PacketParser::parse(bytes);
  ASSERT_TRUE(parsed.has_value());
  EXPECT_EQ(parsed->session_id, 0xFFFFFFFFFFFFFFFFULL);
  EXPECT_EQ(parsed->sequence, 0x123456789ABCDEF0ULL);
}

TEST(PacketTests, ParsesEmptyFramePayload) {
  packet::PacketBuilder builder;
  builder.set_session_id(1).set_sequence(1);
  builder.add_frame(packet::FrameType::kKeepAlive, {});
  auto bytes = builder.build();
  auto parsed = packet::PacketParser::parse(bytes);
  ASSERT_TRUE(parsed.has_value());
  ASSERT_EQ(parsed->frames.size(), 1U);
  EXPECT_TRUE(parsed->frames[0].data.empty());
}

TEST(PacketTests, ParsesMultipleFrames) {
  packet::PacketBuilder builder;
  builder.set_session_id(1).set_sequence(1);
  std::vector<std::uint8_t> data1{1, 2, 3};
  std::vector<std::uint8_t> data2{4, 5};
  std::vector<std::uint8_t> data3{};
  builder.add_frame(packet::FrameType::kData, data1);
  builder.add_frame(packet::FrameType::kAck, data2);
  builder.add_frame(packet::FrameType::kKeepAlive, data3);
  auto bytes = builder.build();
  auto parsed = packet::PacketParser::parse(bytes);
  ASSERT_TRUE(parsed.has_value());
  ASSERT_EQ(parsed->frames.size(), 3U);
  EXPECT_EQ(parsed->frames[0].type, packet::FrameType::kData);
  EXPECT_EQ(parsed->frames[1].type, packet::FrameType::kAck);
  EXPECT_EQ(parsed->frames[2].type, packet::FrameType::kKeepAlive);
}

TEST(PacketTests, RejectsExtraTrailingBytes) {
  packet::PacketBuilder builder;
  builder.set_session_id(1).set_sequence(1);
  std::vector<std::uint8_t> payload{1, 2, 3};
  builder.add_frame(packet::FrameType::kData, payload);
  auto bytes = builder.build();
  bytes.push_back(0xFF);  // Add extra byte
  auto parsed = packet::PacketParser::parse(bytes);
  EXPECT_FALSE(parsed.has_value());
}

}  // namespace veil::tests
