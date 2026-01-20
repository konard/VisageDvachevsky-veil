#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

namespace veil::crypto {

std::vector<std::uint8_t> random_bytes(std::size_t length);
std::uint64_t random_uint64();
void secure_zero(std::span<std::uint8_t> buffer);

}  // namespace veil::crypto
