#pragma once

#include <chrono>
#include <cstdint>
#include <vector>

namespace veil::mux {

struct DataFrame {
  std::uint64_t stream_id{0};
  std::uint64_t sequence{0};
  bool fin{false};
  std::vector<std::uint8_t> payload;
};

struct AckFrame {
  std::uint64_t stream_id{0};
  std::uint64_t ack{0};
  std::uint32_t bitmap{0};
};

struct ControlFrame {
  std::uint8_t type{0};
  std::vector<std::uint8_t> payload;
};

// Heartbeat frame for keep-alive and obfuscation.
struct HeartbeatFrame {
  std::uint64_t timestamp{0};  // Milliseconds since epoch or relative.
  std::uint64_t sequence{0};   // Heartbeat sequence number.
  std::vector<std::uint8_t> payload;  // Optional fake telemetry data.
};

enum class FrameKind : std::uint8_t { kData = 1, kAck = 2, kControl = 3, kHeartbeat = 4 };

struct MuxFrame {
  FrameKind kind{};
  DataFrame data;
  AckFrame ack;
  ControlFrame control;
  HeartbeatFrame heartbeat;
};

}  // namespace veil::mux
