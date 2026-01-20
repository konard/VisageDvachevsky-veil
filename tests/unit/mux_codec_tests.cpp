#include <gtest/gtest.h>

#include <cstdint>
#include <vector>

#include "transport/mux/mux_codec.h"

namespace veil::tests {

TEST(MuxCodecTests, DataFrameRoundTrip) {
  std::vector<std::uint8_t> payload{0x01, 0x02, 0x03, 0x04};
  auto frame = mux::make_data_frame(42, 100, false, payload);
  auto encoded = mux::MuxCodec::encode(frame);
  auto decoded = mux::MuxCodec::decode(encoded);
  ASSERT_TRUE(decoded.has_value());
  EXPECT_EQ(decoded->kind, mux::FrameKind::kData);
  EXPECT_EQ(decoded->data.stream_id, 42U);
  EXPECT_EQ(decoded->data.sequence, 100U);
  EXPECT_FALSE(decoded->data.fin);
  EXPECT_EQ(decoded->data.payload, payload);
}

TEST(MuxCodecTests, DataFrameWithFin) {
  std::vector<std::uint8_t> payload{0xAA, 0xBB};
  auto frame = mux::make_data_frame(1, 50, true, payload);
  auto encoded = mux::MuxCodec::encode(frame);
  auto decoded = mux::MuxCodec::decode(encoded);
  ASSERT_TRUE(decoded.has_value());
  EXPECT_TRUE(decoded->data.fin);
}

TEST(MuxCodecTests, AckFrameRoundTrip) {
  auto frame = mux::make_ack_frame(7, 200, 0xDEADBEEF);
  auto encoded = mux::MuxCodec::encode(frame);
  auto decoded = mux::MuxCodec::decode(encoded);
  ASSERT_TRUE(decoded.has_value());
  EXPECT_EQ(decoded->kind, mux::FrameKind::kAck);
  EXPECT_EQ(decoded->ack.stream_id, 7U);
  EXPECT_EQ(decoded->ack.ack, 200U);
  EXPECT_EQ(decoded->ack.bitmap, 0xDEADBEEFU);
}

TEST(MuxCodecTests, ControlFrameRoundTrip) {
  std::vector<std::uint8_t> payload{0x10, 0x20, 0x30};
  auto frame = mux::make_control_frame(0x05, payload);
  auto encoded = mux::MuxCodec::encode(frame);
  auto decoded = mux::MuxCodec::decode(encoded);
  ASSERT_TRUE(decoded.has_value());
  EXPECT_EQ(decoded->kind, mux::FrameKind::kControl);
  EXPECT_EQ(decoded->control.type, 0x05);
  EXPECT_EQ(decoded->control.payload, payload);
}

TEST(MuxCodecTests, RejectsEmptyData) {
  auto decoded = mux::MuxCodec::decode({});
  EXPECT_FALSE(decoded.has_value());
}

TEST(MuxCodecTests, RejectsTruncatedDataFrame) {
  std::vector<std::uint8_t> payload{0x01, 0x02};
  auto frame = mux::make_data_frame(1, 1, false, payload);
  auto encoded = mux::MuxCodec::encode(frame);
  encoded.pop_back();  // Remove one byte to make it truncated
  auto decoded = mux::MuxCodec::decode(encoded);
  EXPECT_FALSE(decoded.has_value());
}

TEST(MuxCodecTests, RejectsTruncatedAckFrame) {
  auto frame = mux::make_ack_frame(1, 1, 0);
  auto encoded = mux::MuxCodec::encode(frame);
  encoded.pop_back();
  auto decoded = mux::MuxCodec::decode(encoded);
  EXPECT_FALSE(decoded.has_value());
}

TEST(MuxCodecTests, RejectsUnknownFrameKind) {
  std::vector<std::uint8_t> data{0xFF, 0x00, 0x00};  // Unknown kind
  auto decoded = mux::MuxCodec::decode(data);
  EXPECT_FALSE(decoded.has_value());
}

TEST(MuxCodecTests, EncodedSizeIsAccurate) {
  std::vector<std::uint8_t> payload{1, 2, 3, 4, 5};
  auto data_frame = mux::make_data_frame(1, 1, true, payload);
  EXPECT_EQ(mux::MuxCodec::encoded_size(data_frame), mux::MuxCodec::encode(data_frame).size());

  auto ack_frame = mux::make_ack_frame(2, 3, 0x12345678);
  EXPECT_EQ(mux::MuxCodec::encoded_size(ack_frame), mux::MuxCodec::encode(ack_frame).size());

  auto ctrl_frame = mux::make_control_frame(0x01, payload);
  EXPECT_EQ(mux::MuxCodec::encoded_size(ctrl_frame), mux::MuxCodec::encode(ctrl_frame).size());
}

TEST(MuxCodecTests, EmptyDataFramePayload) {
  auto frame = mux::make_data_frame(123, 456, false, {});
  auto encoded = mux::MuxCodec::encode(frame);
  auto decoded = mux::MuxCodec::decode(encoded);
  ASSERT_TRUE(decoded.has_value());
  EXPECT_TRUE(decoded->data.payload.empty());
}

TEST(MuxCodecTests, EmptyControlFramePayload) {
  auto frame = mux::make_control_frame(0x00, {});
  auto encoded = mux::MuxCodec::encode(frame);
  auto decoded = mux::MuxCodec::decode(encoded);
  ASSERT_TRUE(decoded.has_value());
  EXPECT_TRUE(decoded->control.payload.empty());
}

TEST(MuxCodecTests, LargeStreamIdAndSequence) {
  auto frame = mux::make_data_frame(0xFFFFFFFFFFFFFFFF, 0x123456789ABCDEF0, false, {0x42});
  auto encoded = mux::MuxCodec::encode(frame);
  auto decoded = mux::MuxCodec::decode(encoded);
  ASSERT_TRUE(decoded.has_value());
  EXPECT_EQ(decoded->data.stream_id, 0xFFFFFFFFFFFFFFFFULL);
  EXPECT_EQ(decoded->data.sequence, 0x123456789ABCDEF0ULL);
}

}  // namespace veil::tests
