#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "common/obfuscation/obfuscation_profile.h"

namespace veil::packet {

enum class FrameType : std::uint8_t {
  kData = 0x01,
  kAck = 0x02,
  kKeepAlive = 0x03,
  kHeartbeat = 0x04,
  kPadding = 0xFF,
};

struct Frame {
  FrameType type{};
  std::vector<std::uint8_t> data;
};

struct Packet {
  std::uint8_t version{1};
  std::uint8_t flags{0};
  std::uint64_t session_id{0};
  std::uint64_t sequence{0};
  std::vector<Frame> frames;
};

class PacketBuilder {
 public:
  PacketBuilder& set_session_id(std::uint64_t id);
  PacketBuilder& set_sequence(std::uint64_t seq);
  PacketBuilder& set_flags(std::uint8_t flags);
  PacketBuilder& add_frame(FrameType type, std::span<const std::uint8_t> data);
  PacketBuilder& add_padding(std::size_t bytes);

  // Add obfuscation profile for HMAC-based prefix/padding.
  PacketBuilder& set_obfuscation_profile(const obfuscation::ObfuscationProfile* profile);

  // Add deterministic prefix based on profile seed and sequence.
  PacketBuilder& add_profile_prefix();

  // Add deterministic padding based on profile seed and sequence.
  PacketBuilder& add_profile_padding();

  // Add heartbeat frame with optional payload.
  PacketBuilder& add_heartbeat(std::span<const std::uint8_t> payload = {});

  std::vector<std::uint8_t> build() const;

  static constexpr std::array<std::uint8_t, 2> magic() { return {0x56, 0x4C}; }

 private:
  Packet packet_{};
  const obfuscation::ObfuscationProfile* profile_{nullptr};
  std::vector<std::uint8_t> prefix_;
};

class PacketParser {
 public:
  static std::optional<Packet> parse(std::span<const std::uint8_t> buffer);
};

}  // namespace veil::packet
